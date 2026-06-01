def generate_rollback_instructions(backup_name: str = "pre_repair") -> str:
    return f"""# =====================================================================
# SAFE MODE BACKUP & ROLLBACK INSTRUCTIONS
# Run the backup commands BEFORE applying any remediation scripts.
# =====================================================================
# CREATE BACKUP:
# /system backup save name={backup_name}
# /export file={backup_name}_export
#
# ROLLBACK ACTION (IF CONNECTIVITY IS LOST):
# 1. Connect to the MikroTik router via MAC Winbox, MAC Telnet, or Console.
# 2. Restore the binary backup using the command below:
#    /system backup load name={backup_name}.backup
# =====================================================================
"""
