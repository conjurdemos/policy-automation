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
> **Example of record checked by Host-Automation service (in JSON format)**
> ```   
> {
>       "created_at": "2019-10-31T14:37:00.878+00:00",
>       "id": "conjur:group:vault/LOBName/SafeName/delegation/consumers",
>       "policy": "conjur:policy:vault/LOBName/SafeName/delegation",
>       "members": [
>           {
>               "admin_option": true,
>               "ownership": true,
>               "role": "conjur:group:vault/LOBName/SafeName/delegation/consumers",
>               "member": "conjur:policy:vault/LOBName/SafeName/delegation",
>               "policy": "conjur:policy:vault/LOBName/SafeName/delegation"
>           }
>       ]
> }
> ```
- This logic tells the automation we need to create a host and add an entitlement. If the pattern matches an existing host identity (APPID) but has a different IDENTIFIER it will not create a new host but will entitle an existing host to this group:
   - Automation will parse the url and extract `SafeName`
    - The Host will be named to the `SafeName`
- Automation will then build the policy files:
   - Host declaration with creation timestamp
   - This host will be onboarded to a predefined authenticators group
   - The host will attempt to be loaded into Conjur
    - If successful, the host will then onboard to PVWA
    - If unsuccessful, the automation will terminate and not entitle as it could not protect the credential
      - If this happens, the script will attempt to delete the host from Conjur so that it can be rerun after the underlying issue has been fixed (safe permissions, pasObject password auth failure, etc.)
   
> - Once the host has been onboarded into PVWA, it will entitle the host to credentials
> - The host will be entitled with least privilege in mind, loading the policy into the target safe delegation branch

## Limitations

The Host automation does not handle annotations outside of creation timestamp. This automation is intended to onboard host/api keys autonomously and provided as a proof of concept for process.

## Requirements

- Configured Conjur environment (leaders + followers)
- Functioning Synchronizer Service
- Configured Credential Provider for the machine the automation is running on. See CyberArk Professional Services for support.
- Ask your CyberArk representative for access to the "CyberArk Conjur" safe
- A safe in PVWA called "Conjur-Automation", with two accounts added - ConjurHostsAccess and ConjurAutomation:
  - ***ConjurHostsPlugin.zip*** PVWA Imported Platform has been enabled and fully configured.
  - ``ConjurHostsAccess`` account, which will provide access to PVWA
  - ``ConjurAutomation`` account, which will provide access to Conjur

> **Note**: The download of the ***ConjurHostsPlugin.zip*** can be found in the Support Vault -> CyberArk Conjur safe, at folder 'CPM Plugin' at the [Secure File Exchange (SFE)](https://support.cyberark.com/SFE/Logon.aspx). The instructions on how to install are in  ***Conjur Hosts Plugin Implementation Guide.pdf*** and in [1. Prepare PVWA for Conjur Host Automation](https://github.com/ztwright/policy-automation#1-prepare-pvwa-for-conjur-host-automation).
> 1. In PVWA, add an account with platform type of `CyberArk Vault` and store it in the *conjur-automation* safe.
> 2. In PVWA, add an account with platform type 'ConjurHostsViaRest' or its configured duplicate and store it in the "Conjur-Automation" safe.
> 3. The `ConjurHostsAccess` Account must be added to the **Conjur-Automation** safe in PrivateArk vault before being added in PVWA (where applicable).

> **ConjurHostsAccess Config**
> | Attribute           | Value                             |
> | ------------------- | :-------------------------------- |
> | System Type         | Application                       |
> | Assign to Platform  | CyberArk Vault (or duplication)   |
> | Address             | `{{ privateark-vault-url }}`      |
> | Username            | ConjurHostsAccess                 |
> 
> **Notes**
> 
> 1. Check the box next to 'Customize Account Name', and give it the same name as Username (ConjurHostsAccess).
>
> 2. This user needs to have permissions to see and update the safe that the LOB has been added to. If it does not, it will not be able to onboard the host into the safe properly.
> 
> 3. This account must be added via PrivateArk client interface to the `*Conjur-Automation*` safe *first* in order for the automation to facilitate actions against the vault.
>
> Once the account has been created, add it as a member  to `Conjur-Automation` safe with the following privileges:
>
> | Access   | | Account management        | | Workflow                         | | Advanced        | 
> | -------- | | ------------------------- | | ------------------------------   | | --------------- |
> | List     | | Add accounts              | | Access safe without confirmation | | Create folders  |
> | Use      | | Update account properties |                                      | Delete folders  |
> | Retrieve | | Update account content    |
> ***
> **ConjurAutomation Config**
> | Attribute           | Value                                  |
> | ------------------- | :--------------------------------      |
> | System Type         | Application                            |
> | Assign to Platform  | Conjur Hosts Via REST (or duplication) |
> | Address             | `{{ conjur-leader-glb }}:443`          |
> | Host                | ConjurAutomation                       |
> 
> **Note**: Check the box next to 'Customize Account Name', and give it the same name as Username (`ConjurAutomation`).
>
> **Additional Note**: The script adds `host/` into the host. Therefore, it is not necessary to add that as a value when onboarding to our *Conjur-Automation* safe.
>
> **Important**: The script does not support `user` for use in automation.

> ***
> **Important**: Both accounts **must** be added to the safes the automation acting upon, with the following permissions:
> 
> | Access   |
> | -------- |
> | List     |
> | Use      |
> | Retrieve |
> 
> ***

## Usage instructions

### 1. Prepare PVWA for Conjur Host Automation

- Set up Conjur Host CP Plugin
   - Download the Conjur Host CP Plugin (for additional instructions see section [Requirements](https://github.com/ztwright/policy-automation#Requirements)
   - Import the platform into PVWA
   - Duplicate, activate and rename the platform to match current standards in the environment
      - For easability, it is recommended to rename this to a name without spaces or special characters
         - For Example: `ConjurHostsCPMPlugin`
   - Edit the Duplicated platform
      - Under Additional Settings
         - Find `AccountName` parameter, and change from `TBD` to match your current **Conjur Organization Account** (i.e., *prod*)
   - Take note of the renamed platform
- Validate CPM, PVWA and Synchronizer connectivity:

 | Component        | Needs to reach...    | via Port          | Operation
 | :--------------- | :------------------- | :---------------: | -----------
 | CPM              | Conjur leader GLB    | `443`             | `n/a`
 | Host-Automation  | Conjur leader GLB    | `443`             | `write`
 | Host-Automation  | Conjur follower GLB  | `443`             | `read`
 | Host-Automation  | PVWA                 | `443`             | `write`

### 2. Configuring Conjur Policy

- Update and load the policy under the `Policy` Directory
   - The value for `Sync_{{SyncHostName}}` must **match** what has already been configured for your existing Synchronizer implementation
> For instance, if the {{SyncHostName}} was `PVWA-Cybr-Host-1`, then all instances in `Policy/01_root-sync.yml` would be replaced, such as the following:
>
> ```
> 1  \# Policy stub to persist synchronizer configuration
> 2
> 3  - !host Sync_PVWA-Cybr-Host-1
> ...
> ```

   - The value for {{vault-id}}_admins should similarly **match** the vault alias from setup of the synchronizer
> For instance, if the {{vault-id}} was `Vault`, then all instances in Policy/01_root-sync & 02_root-apps.yml would be replaced, such as the following:
>
> ```
> ...
> 5  - !group Vault-admins
> ...
> ```

   - Capture the credentials created for the `conjur-automation` host.
   - This policy must be loaded into `root` policy branch.
   - Update the api-key of created *ConjurAutomation* account object in the `Conjur-Automation` safe

### 3. Prepare Automation to Run

- Enable logging
  - There are two logging formats in the automation:
    1.  Windows Event Viewer (persistent) and 
    2. Console Output (non-persistent)
  - Before running the automation the application must be registered as an application in Windows Event Viewer
    - Open Powershell as administrator and run the following command:
    `New-EventLog -Source "Conjur Onboarding Service" -LogName Application`
    - Close the Administrator session

> Now that the logging service is set up, all actions will be shipped to Windows Event Viewer and can be filtered by `Conjur Onboarding Service`.

- Update `Automation/config.json`:
   - Update `"authn"` section, definitions below:

 | attribute                | value             | definition                |
 | :----------------------- | :---------------- | :------------------------ |
 | `"type"`                 | provider          | `provider` is the only value supported and should not change |

   - Update `"authn_config"` definitions as follows:

 | attribute                | value                    | definition                |
 | :----------------------- | ------------------------ | :----------------------------- |
 | `"automation_safe"`      | `Conjur-Automation`      | The safe that the CP has access to [^1] |
 | `"conjurObject"`         | `ConjurAutomation`       | The object that holds the `Conjur` authentication info |
 | `"pasObject"`            | `ConjurHostsAccess`      | The object that holds the `PrivateArk Vault` authentication info |
 | `"appID"`                | `ConjurHostAutomation`   | The application-id associated with the CP Application in PVWA |
 | `"cpPath"`               | `C:\\Program Files\\CyberArk\\ApplicationPasswordSdk\\CLIPasswordSDK.exe`[^2] | The `Credential Provider SDK` path (.exe included) |

> [^1]: This is the safe that was set up as part of fullfillment of the [Requirements](https://github.com/ztwright/policy-automation#Requirements) section.
> [^2]: The double `\`, this escaped the slash and allows the objects to be called correctly, else the json will be malformed.

   - Update `"conjur"` section, definitions below:

 | attribute                | value                            | definition                |
 | :----------------------- | :------------------------------- | :------------------------ |
 | `"master"`               | `cnjr-lead.example.com`          | The top-level DNS for the leader GLB [^3] |
 | `"follower"`             | `cnjr-follow.example.com`        | The top-level DNS for the follower GLB [^4] |
 | `"account"`              | `default`                        | The Conjur Organization account (*i.e., `prod`*) |
 | `"branch"`               | `apps`                           | Target policy branch for apps to be onboarded to |
 | `"cleanup"`              | `false`                          | Cleans up local policy files created during automation [^5] |

> [^3]: `Write` operations can only be handled on Conjur leader cluster
> [^4]: `Read` operations are optimized, driving these requests towards read-only replica sets (followers)
> [^5]: It is recommended to set `cleanup` value to `true`

   - Update `"pvwa"` section, definitions below:

 | attribute                | value                            | definition                |
 | :----------------------- | :------------------------------- | :------------------------ |
 | `"url"`                  | `pvwa.example.com`               | The top-level DNS of the PVWA target to onboard created hosts |
 | `"platform"`             | `ConjurHostsCPMPlugin`           | The platform being leveraged to handle automation [^6] |

> [^6]: This must match the platform name in the definition of the `ConjurAutomation` object. 

## Running the Host-Automation

In order to run the automation, open a Powershell window as a service account at the following location: `{{ install-partition }}:\Program Files\Host-Automation\Automation`

Execute the following to run the automation:
```
.\onboarding-service.ps1
```

## Operationalizing the Host-Automation through the Windows Task Scheduler

Once the automation has been tested one-time manually with success, setting up operationally with the Windows Task Scheduler is the next optional path. Follow [this link](https://github.com/conjurdemos/policy-automation/blob/main/SCHEDULED-TASK-SETUP.md) for more information. 

> **Disclaimer**: Not developed nor tested for Production instances. 

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
