use anyhow::anyhow;
use configparser::ini::Ini;
use futures::StreamExt;
use indexmap::IndexMap;
use std::{thread, time};

#[derive(Debug)]
pub struct SSOProfile {
    pub account_id: String,
    pub account_name: String,
    pub role_name: String,
    pub start_url: String,
    pub sso_region: String,
}

impl From<&SSOProfile> for IndexMap<String, Option<String>> {
    fn from(sso_profile: &SSOProfile) -> Self {
        let mut section: IndexMap<String, Option<String>> = IndexMap::new();
        section.insert(String::from("sso_start_url"), Some(sso_profile.start_url.clone()));
        section.insert(String::from("sso_region"), Some(sso_profile.sso_region.clone()));
        section.insert(String::from("sso_account_id"), Some(sso_profile.account_id.clone()));
        section.insert(String::from("sso_role_name"), Some(sso_profile.role_name.clone()));

        section
    }
}

pub struct SSOProfilesLister {
    sso_region: String,
    start_url: String,
}

impl SSOProfilesLister {
    pub fn new(start_url: &str, sso_region: &str) -> Self {
        SSOProfilesLister {
            sso_region: String::from(sso_region),
            start_url: String::from(start_url),
        }
    }

    /// Lists the AWS SSO profiles.
    pub async fn list(&self) -> Result<Vec<SSOProfile>, anyhow::Error> {
        let sdk_config = aws_config::from_env()
            .region(aws_types::region::Region::new(self.sso_region.clone()))
            .load()
            .await;

        let access_token = self.device_code_flow(&sdk_config).await?;
        
        let sso_profiles = self.list_sso_profiles(&sdk_config, access_token.as_str()).await?;
        
        Ok(sso_profiles)
    }

    /// Handles AWS SSO's Device Code Flow, returning an access token result.
    async fn device_code_flow(&self, sdk_config: &aws_config::SdkConfig) -> Result<String, anyhow::Error> {
        let sso_client_oidc = aws_sdk_ssooidc::Client::new(sdk_config);

        let register = sso_client_oidc
            .register_client()
            .client_name("profile-sync-client")
            .client_type("public")
            .scopes("sso-portal:*")
            .send()
            .await?;

        let client_id = register
            .client_id()
            .ok_or_else(|| anyhow!("SSO Client Registration provided no client id"))?;
        let client_secret = register
            .client_secret()
            .ok_or_else(|| anyhow!("SSO Client Registration provided no client secret"))?;

        let device_authorization = sso_client_oidc
            .start_device_authorization()
            .client_id(client_id)
            .client_secret(client_secret)
            .start_url(&self.start_url)
            .send()
            .await?;

        let verification_uri = device_authorization
            .verification_uri_complete()
            .ok_or_else(|| anyhow!(
                "SSO Device Authorization provided no verification URL"
            ))?;

        let device_code = device_authorization
            .device_code()
            .ok_or_else(|| anyhow!("SSO Device Authorization provided no device code"))?;

        match open::that(verification_uri) {
            _ => {
                bunt::eprintln!("{$cyan+bold}Open the following link, if it doesn't open automatically, to allow access to SSO:{/$}");
                eprintln!("{}", verification_uri);
            }
        }

        let token_output = loop {
            thread::sleep(time::Duration::from_millis(1000));

            let res = sso_client_oidc
                .create_token()
                .client_id(client_id)
                .client_secret(client_secret)
                .device_code(device_code)
                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                .send()
                .await;

            match res {
            Ok(x) => break Ok(x),
            Err(err) => match err {
                aws_sdk_ssooidc::types::SdkError::ServiceError{raw: _, err} =>  match err.kind {
                    aws_sdk_ssooidc::error::CreateTokenErrorKind::AuthorizationPendingException(_) => continue,
                    _ => break Err(anyhow!(err))
                },
                _ => break Err(anyhow!(err)),
            }
        };
        }?;

        let access_token = token_output
            .access_token()
            .ok_or_else(|| anyhow!("Token output provided no access token"))?;

        Ok(String::from(access_token))
    }

    /// Query the SSO profiles with an access token.
    async fn list_sso_profiles(&self, sdk_config: &aws_config::SdkConfig, access_token: &str) -> Result<Vec<SSOProfile>, anyhow::Error> {
        bunt::eprintln!("{$cyan+bold}Finding accounts and roles{/$}");
        let mut sso_profiles = Vec::<SSOProfile>::new();

        let sso_client = aws_sdk_sso::Client::new(sdk_config);

        let mut accounts = sso_client
            .list_accounts()
            .access_token(access_token)
            .into_paginator()
            .items()
            .send();

        while let Some(account) = accounts.next().await {
            let account = account?;
            let account_id = account
                .account_id()
                .ok_or_else(|| anyhow!("Account id is missing"))?;
            let account_name = account
                .account_name()
                .ok_or_else(|| anyhow!("Account is missing its name"))?;

            let mut list_roles = sso_client
                .list_account_roles()
                .access_token(access_token)
                .account_id(account_id)
                .into_paginator()
                .send();

            while let Some(list_roles) = list_roles.next().await {
                for role in list_roles?
                    .role_list()
                    .ok_or_else(|| anyhow!("Role list not available"))?
                {
                    let role_name = role
                        .role_name()
                        .ok_or_else(|| anyhow!("Role does not have a name"))?;
                    
                    sso_profiles.push(SSOProfile {
                        account_id: String::from(account_id),
                        account_name: String::from(account_name),
                        role_name: String::from(role_name),
                        sso_region: String::from(&self.sso_region),
                        start_url: String::from(&self.start_url),
                    });
                }
            }
        }

        Ok(sso_profiles)
    }
}

pub struct AwsConfigMerger {
    pub prefix: String,
    pub clean: bool,
}

impl AwsConfigMerger {
    pub fn merge(&self, sso_profiles: &Vec<SSOProfile>, ini: &mut Ini) -> Result<(), anyhow::Error> {
        let ini_map = ini.get_mut_map();

        if self.clean {
            let keys: Vec<String> = ini_map.keys()
                .cloned()
                .collect();

            let prefix = self.section_name(&self.prefix_name(""));
            
            for key in keys {
                if key.starts_with(&prefix) {
                    ini_map.remove(&key);
                }
            }
        }
        
        for sso_profile in sso_profiles {
            let bare_profile_name = format!("{}-{}", sso_profile.account_name.replace(' ', "-"), &sso_profile.role_name);
            let profile_name = self.prefix_name(&bare_profile_name);
            let section_name = self.section_name(&profile_name);
            
            // Resolve conflicts by overwriting with the new profile
            if ini_map.contains_key(&section_name) {
                ini_map.remove(&section_name);
            }

            bunt::eprintln!("{$green}Profile{/$} {[white+bold]}", profile_name);
    
            ini_map.insert(String::from(&section_name), sso_profile.into());
        }

        Ok(())
    }

    fn prefix_name(&self, profile_name: &str) -> String {
        format!("{}{}", &self.prefix, profile_name)
    }

    fn section_name(&self, profile_name: &str) -> String {
        format!("profile {}", profile_name)
    }
}