# Automating Host-Policy Through the Windows Task Scheduler

Adding a scheduled task to perform the host-automation on a predetermined frequency.

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

- Select the **Triggers** tab -> *New...*

![image-4]

- Copy the settings in the screenshot below

![image-5]

- Select **Actions** tab -> *New...*

![image-6]

- Under *New Action*, copy the settings so they are identical to the screenshot below, including the following:

 | attribute                | value             |
 | :----------------------  | :---------------- |
 | Add arguments (optional) | `-ExecutionPolicy Bypass C:\Program Files\Host Automation\Automation\onboarding-service.ps1` |

![image-7]



[image-1]: https://github.com/ztwright/policy-automation/blob/main/images/host-auto-folder.png

[image-2]: https://github.com/ztwright/policy-automation/blob/main/images/find-task-sched.png

[image-3]: https://github.com/ztwright/policy-automation/blob/main/images/create-task.png

[task]: https://github.com/ztwright/policy-automation/blob/main/images/task.png

[image-4]: https://github.com/ztwright/policy-automation/blob/main/images/trigger.png

[image-5]: https://github.com/ztwright/policy-automation/blob/main/images/trigger-settings.png

[image-6]: https://github.com/ztwright/policy-automation/blob/main/images/action.png

[image-7]: https://github.com/ztwright/policy-automation/blob/main/images/set-exec-policy.png

