# Automating Host-Policy Through the Windows Task Scheduler

Adding a scheduled task to perform the host-automation on a predetermined frequency.

> ***Dislaimer***: Not developed nor tested for Production instances. 

## Setting up

- Move the automation install bundle to the following location:
```
{{ install-partition }}:\Program Files\CyberArk\
```
![image-1]



- Open the Windows Task Scheduler

![image-2]



- Select ![task] *Create Task...*

![image-3]



- Under **General** tab, copy the settings from below.

![general]

> **Note**: This documentation was put together for demonstration purposes. You should *_never_* run a scheduled task as anything except for an account managed by the Password Manager (CPM) and managed centrally from the Vault. 



- Select the **Triggers** tab -> *New...*

![image-4]



- Copy the settings in the screenshot below -> `OK`

![image-5]



- Select **Actions** tab -> *New...*

![image-6]



- In *Edit Action* window, copy the settings so they are identical to the screenshot below, including the following:

 | attribute                | value             |
 | :----------------------  | :---------------- |
 | Add arguments (optional) | `-ExecutionPolicy Bypass "{{ partition-letter }}:\Program Files\Host Automation\Automation\onboarding-service.ps1"`  |

![image-7]



# Testing

To test the job, simply right click the job in Task Scheduler -> `Run`

![image-8]



[image-1]: https://github.com/ztwright/policy-automation/blob/main/images/host-auto-folder.png

[image-2]: https://github.com/ztwright/policy-automation/blob/main/images/find-task-sched.png

[image-3]: https://github.com/ztwright/policy-automation/blob/main/images/create-task.png

[task]: https://github.com/ztwright/policy-automation/blob/main/images/task.png

[image-4]: https://github.com/ztwright/policy-automation/blob/main/images/trigger.png

[image-5]: https://github.com/ztwright/policy-automation/blob/main/images/trigger-settings.png

[image-6]: https://github.com/ztwright/policy-automation/blob/main/images/action.png

[image-7]: https://github.com/ztwright/policy-automation/blob/main/images/set-exec-policy.png

[image-8]: https://github.com/ztwright/policy-automation/blob/main/images/run-task.png

[general]: https://github.com/ztwright/policy-automation/blob/main/images/general-tab.png

