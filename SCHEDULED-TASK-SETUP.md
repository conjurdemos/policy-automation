# Automating Host-Policy Through the Windows Task Scheduler

Adding a scheduled task to perform the host-automation on a predetermined frequency.

> ***Dislaimer***: Not developed nor tested for Production instances. 


## Setting up

- Move the automation install bundle to the following location:
```
{{ install-partition }}:\Program Files\CyberArk\
```
<img src=images/host-auto-folder.png width="500" height="250">

- Open the Windows Task Scheduler

<img src=images/find-task-sched.png width="500" height="250">

- Select <img src=images/task.png width="50" height="50"> *Create Task...*

<img src=images/create-task.png width="500" height="250">

- Under **General** tab, copy the settings from below.

<img src=images/general-tab.png width="500" height="250">

> **Note**: This documentation was put together for demonstration purposes. You should *_never_* run a scheduled task as anything except for an account managed by the Password Manager (CPM) and managed centrally from the Vault. 

- Select the **Triggers** tab -> *New...*

<img src=images/trigger.png width="500" height="250">

- Copy the settings in the screenshot below -> `OK`

<img src=images/trigger-settings.png width="500" height="250">

- Select **Actions** tab -> *New...*

<img src=images/action.png width="500" height="250">

- In *Edit Action* window, copy the settings so they are identical to the screenshot below, including the following:

 | attribute                | value             |
 | :----------------------  | :---------------- |
 | Add arguments (optional) | `-ExecutionPolicy Bypass "{{ partition-letter }}:\Program Files\Host Automation\Automation\onboarding-service.ps1"`  |

<img src=images/set-exec-policy.png width="500" height="250">


# Testing

To test the job, simply right click the job in Task Scheduler -> `Run`

