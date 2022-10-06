# Host API Key Automation
Host API Key policy onboarding automation for Conjur.

## Certification level

![](https://img.shields.io/badge/Certification%20Level-Community-28A745?link=https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

This repo is a **Community** level project. It's a community contributed project that **is not reviewed or supported
by CyberArk**. For more detailed information on our certification levels, see [our community guidelines](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md#community).

## Process

- The automation checks the *delegation/consumers* group that is **created and managed by the `Synchronizer`**.
- The **first** check is group members length is equal to 1. 
- The **second** check is if this group has admin_option to true. Please see the example output below:
```json
   {
       "created_at": "2019-10-31T14:37:00.878+00:00",
       "id": "conjur:group:vault/LOBName/SafeName/delegation/consumers",
       "policy": "conjur:policy:vault/LOBName/SafeName/delegation",
       "members": [
           {
               "admin_option": true,
               "ownership": true,
               "role": "conjur:group:vault/LOBName/SafeName/delegation/consumers",
               "member": "conjur:policy:vault/LOBName/SafeName/delegation",
               "policy": "conjur:policy:vault/LOBName/SafeName/delegation"
           }
       ]
   }
```
- This logic tells the automation we need to create a host and add an entitlement. If the pattern matches an existing host identity (APPID) but has a different IDENTIFIER it will not create a new host but will entitle an existing host to this group:
   - Automation will parse the url and extract `SafeName`
      - The Host will be named to the `SafeName`
- Automation will then build the policy files:
   - Host declaration with creation timestamp
   - This host will be onboarded to a predefined authenticators group
   - The host will attempt to be loaded into Conjur
      - If successful, the host will then onboard to PVWA
      - If unsuccsseful, the automation will terminate and not entitle as it could not protect the credential
         - If this happens, the host needs to be deleted in conjur and the permissions on the accounts used must be fixed to proceed
   - Once the host has been onboarded into PVWA, it will entitle the host to credentials
      - The host will be entitled with least privilege in mind, loading the policy into the target safe delegation branch

## Limitations
The Host automation does not handle annotations outside of creation timestamp. This automation is intended to onboard host/api keys autonomously and provided as a proof of concept for process.

## Requirements

- Configured Conjur environment
- Functioning Synchronizer Service
- Configured Credential Provider for the machine the automation is running on


## Usage instructions

### 1. Prepare PVWA for Conjur Host Automation

- Set up Conjur Host CPM Plugin
   - Download the Conjur Host CPM Plugin
   - Import the platform into PVWA
   - Duplicate, activate and rename the platform to match current standards in the environment
      - For easability, it is recommended to rename this to a name without spaces or special characters
         - For Example: `ConjurHostsCPMPlugin`
   - Edit the Duplicated platform
      - Under Additional Settings
         - Find account, change from TBD to match your current **Conjur Organization Account**
   - Take note of the renamed platform
- Validate CPM, PVWA and Synchronizer connectivity
   - The CPM needs to be able to reach Conjur Leader Load Balancer on Port 443
   - The automation needs to be able to Reach the Conjur Leader Load Balancer on port 443 for write operations
   - The automation needs to be able to Reach the Conjur Follower Load Balancer on port 443 for read operations
   - The automation needs to be able to Reach PVWA on port 443 for write operations

### 2. Configuring Conjur Policy

- Update and load the policy under the `Policy` Directory
   - The value for ` Sync_{{SyncHostName}}` must **match** what is already configured for your existing Synchronizer implementation.
   - Capture the credentials created for the `conjur-automation` host.
   - This policy must be loaded into `root` policy branch.
- Onboard `conjur-automation` in the vault for rotation
   - Using the Conjur Host CPM Plugin, onboard the credentials and rotate the credential.
      - This ensures we can manage the automation host and rotate under change control for compliancy.
      - This will also validate the CPM can interact with Conjur and manage created host API Keys

### 3. Prepare Automation to Run

- Enable logging
   - There are two logging formats in the automation, Windows Event Viewer (persistent) and Console Output (non-persistent)
      - Before running the automation the application must be registered as an application in Windows Event Viewer
         - Open Powershell as administrator and run the following command
            > New-EventLog -Source "Conjur Onboarding Service" -LogName Application
         - Close the Administrator session.
      - Now that the logging service is set up, all actions will be shipped to Windows Event Viewer and can be filtered by `Conjur Onboarding Service`
- Update `config.json`
   - Update `"authn"` section, definitions below:
      - `"type"`: provider is the only value currently supported and should not change.
      - `"authn_config"` definitions as followed:
         - `"automation_safe"`: The safe that the credential provider has access to. This safe will hold the `conjur host` and `vault user` the automation will use. 
         - `"conjurObject"`: The object name that holds the `conjur` authentication information.
            - `host`: the host configured in policy
               - Example: `conjur-automation`
               - Note, the script adds `host/` into the host, so it is not necessary to add that as a value when onboarding. The script does not support `user` for use in automation.
            - `apikey`: the current api key for the host or user running the automation
         - `"pasObject"`: The object name that holds the `vault` authentication information.
            - `login`: the user login information to log into PVWA
               - Example: `Sync_HostName`
            - `password`: the password for the above user
            - This user needs to have permissions to see and update the safe that the LOB has been added to. If it does not, it will not be able to onboard the host into the safe properly.
         - `"appID"`: The application ID associated with the CP and the script to retrieve credentials.
         - `"cpPath"`: The `Credential Provider` SDK path (.exe included). This is value needs to be escaped properly or the json will be malformatted.
            - Example: `C:\\Program Files\\CyberArk\\ApplicationPasswordSdk\\CLIPasswordSDK.exe`
               - Note the double `\`, this escaped the slash and allows the objects to be called correctly.
   - Update `"conjur"` section, definitions below:
      - `master`: the dns of the top level domain for the master load balancer
         - Example: `global.conjur-lead.domain.com`
         - Write operations can only be handled on Conjur Master cluster
      - `follower`: the dns of the top level domain for the follower load balancer
         - Example: `global.conjur-follower.domain.com`
         - Read operations are driven to followers for efficiency
      - `account`: the Conjur Organization Account
         - Example: prod
      - `branch`: target policy branch for applications to be onboarded to
         - Example: apps
      - `cleanup`: manages local policy files
         - Accepted values: true or false
         - Policy is generated based on API Calls into Conjur. It is recommended to set this value to "true".
   - Update `"pvwa"` section, definitions below:
      - `url`: the dns of the PVWA target to onboard created hosts
         - Example: `pvwa.domain.com`
      - `platform`: the platform being used to handle automation
         - This must match exactly from the configuration steps above.

You should now be able to run the automation.

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions
of our development workflows, please see our [contributing guide](CONTRIBUTING.md).

## License

Copyright (c) 2022 CyberArk Software Ltd. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

For the full license text see [`LICENSE`](LICENSE).
