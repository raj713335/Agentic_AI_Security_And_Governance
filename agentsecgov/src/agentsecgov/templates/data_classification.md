# Data Classification for Agentic AI

| Data Type      | Prompt Allowed | Log Allowed  | Redaction Required |
|----------------|----------------|--------------|--------------------|
| Email          | Sometimes      | No raw value | Yes                |
| Phone          | Sometimes      | No raw value | Yes                |
| Account number | Rarely         | No raw value | Yes                |
| Password       | Never          | Never        | Block              |
| System prompt  | Never          | Never        | Protect            |