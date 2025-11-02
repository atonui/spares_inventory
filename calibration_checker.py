# Schedule this to run daily via cron or task scheduler

import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

load_dotenv()

DATABASE = os.getenv("DATABASE_URL")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL")

def get_calibration_reminder_days():
    """Get the calibration reminder days setting"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT setting_value FROM system_settings 
        WHERE setting_key = 'calibration_reminder_days'
    """)
    result = cursor.fetchone()
    conn.close()
    
    return int(result['setting_value']) if result else 30

def send_calibration_reminder(to_email, equipment_list, user_name):
    """Send calibration reminder email"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"Equipment Calibration Due - {len(equipment_list)} Item(s)"
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    
    # Build equipment table
    equipment_rows = ""
    for eq in equipment_list:
        days_until = (datetime.fromisoformat(eq['next_calibration_date']) - datetime.now()).days
        status_color = "#f59e0b" if days_until <= 7 else "#3b82f6"
        equipment_rows += f"""
        <tr>
            <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">{eq['equipment_name']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">{eq['make']} {eq['model']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">{eq['serial_number']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e5e7eb; color: {status_color}; font-weight: bold;">
                {days_until} days
            </td>
            <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
                {datetime.fromisoformat(eq['next_calibration_date']).strftime('%b %d, %Y')}
            </td>
        </tr>
        """
    
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px; background: #f8f9fa;">
        <div style="max-width: 700px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white;">
                <h2 style="margin: 0;">⚠️ Equipment Calibration Due</h2>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">Action Required</p>
            </div>
            
            <div style="padding: 30px;">
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">
                    Hello {user_name},
                </p>
                
                <p style="font-size: 14px; color: #666; line-height: 1.6; margin-bottom: 20px;">
                    The following equipment assigned to you requires calibration soon:
                </p>
                
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <thead>
                        <tr style="background: #f8f9fa;">
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Equipment</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Make/Model</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Serial #</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Days Until Due</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Due Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        {equipment_rows}
                    </tbody>
                </table>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <p style="margin: 0; color: #92400e; font-size: 14px;">
                        <strong>Important:</strong> Please ensure calibration is scheduled before the due date to maintain equipment compliance.
                    </p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{FRONTEND_URL.replace('/static/index.html', '/static/index.html')}" 
                       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                              color: white; 
                              padding: 14px 32px; 
                              text-decoration: none; 
                              border-radius: 8px;
                              display: inline-block;
                              font-weight: 500;">
                        View Equipment Dashboard
                    </a>
                </div>
                
                <p style="color: #9ca3af; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    This is an automated reminder from the Inventory Management System.<br>
                    If you have questions, please contact your administrator.
                </p>
            </div>
        </div>
      </body>
    </html>
    """
    
    part = MIMEText(html, 'html')
    msg.attach(part)
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Sent reminder to {to_email} for {len(equipment_list)} equipment")
        return True
    except Exception as e:
        print(f"❌ Error sending email to {to_email}: {e}")
        return False

def check_calibration_due():
    """Check for equipment due for calibration and send reminders"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get reminder days setting
    reminder_days = get_calibration_reminder_days()
    check_date = (datetime.now() + timedelta(days=reminder_days)).strftime('%Y-%m-%d')
    
    print(f"Checking for calibrations due within {reminder_days} days (before {check_date})...")
    
    # Get equipment due for calibration
    cursor.execute("""
        SELECT 
            e.*,
            u.email as user_email,
            u.name as user_name
        FROM equipment e
        LEFT JOIN users u ON e.assigned_user_id = u.id
        WHERE e.status = 'active'
        AND e.next_calibration_date IS NOT NULL
        AND e.next_calibration_date <= ?
        AND e.next_calibration_date >= date('now')
        ORDER BY e.assigned_user_id, e.next_calibration_date
    """, (check_date,))
    
    equipment_list = cursor.fetchall()
    
    if not equipment_list:
        print("✅ No equipment due for calibration")
        conn.close()
        return
    
    # Group equipment by user
    equipment_by_user = {}
    admin_equipment = []
    
    for eq in equipment_list:
        eq_dict = dict(eq)
        if eq['assigned_user_id']:
            user_key = (eq['user_email'], eq['user_name'])
            if user_key not in equipment_by_user:
                equipment_by_user[user_key] = []
            equipment_by_user[user_key].append(eq_dict)
        else:
            # Unassigned equipment - notify admin
            admin_equipment.append(eq_dict)
    
    # Send emails to users
    sent_count = 0
    for (user_email, user_name), user_equipment in equipment_by_user.items():
        if send_calibration_reminder(user_email, user_equipment, user_name):
            sent_count += 1
    
    # Send admin notification for unassigned equipment
    if admin_equipment:
        # Get admin emails
        cursor.execute("SELECT email, name FROM users WHERE role = 'admin'")
        admins = cursor.fetchall()
        
        for admin in admins:
            if send_calibration_reminder(admin['email'], admin_equipment, admin['name']):
                sent_count += 1
    
    # Log the check
    cursor.execute("""
        INSERT INTO system_logs (level, component, message, details)
        VALUES (?, ?, ?, ?)
    """, ('INFO', 'calibration_checker', 
          f'Calibration check completed. {len(equipment_list)} equipment due, {sent_count} emails sent',
          f'{{"reminder_days": {reminder_days}, "equipment_count": {len(equipment_list)}}}'))
    
    conn.commit()
    conn.close()
    
    print(f"✅ Calibration check completed. Sent {sent_count} reminder emails")

if __name__ == "__main__":
    check_calibration_due()