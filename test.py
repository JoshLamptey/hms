#!/usr/bin/env python
"""
Test script for SMS Notifications (ARKE SEL)
Run with: python test_sms.py
"""

import os
import sys
import django
import time

# CRITICAL: Set Celery to use Redis BEFORE any imports
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hms.settings')
os.environ['CELERY_BROKER_URL'] = 'redis://192.168.124.92:6379/0'
os.environ['CELERY_RESULT_BACKEND'] = 'redis://192.168.124.92:6379/0'
os.environ['QUEUE_CELERY'] = 'True'

# Now initialize Django
django.setup()

# After Django is set up, import everything
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from celery import current_app

# Import your apps
from apps.notifications.service import NotificationService
from apps.notifications.models import Campaign, Notification
from apps.notifications.tasks import dispatch_campaign_task

User = get_user_model()

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.RESET}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.RESET}")

def print_sms(msg):
    print(f"{Colors.MAGENTA}📱 {msg}{Colors.RESET}")

def print_header(msg):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")

def print_subheader(msg):
    print(f"\n{Colors.YELLOW}{msg}{Colors.RESET}")
    print("-" * 50)

def check_celery_config():
    """Verify Celery is using Redis"""
    print_header("0. CHECKING CELERY CONFIGURATION")
    
    from hms.celery import app
    
    print_info(f"Broker URL: {app.conf.broker_url}")
    print_info(f"Result Backend: {app.conf.result_backend}")
    
    if 'redis' in str(app.conf.broker_url).lower():
        print_success("Celery is using Redis - GOOD!")
        return True
    else:
        print_error(f"Celery is using wrong broker: {app.conf.broker_url}")
        print_info("Expected: redis://192.168.124.92:6379/0")
        return False

def check_sms_configuration():
    """Check SMS configuration in settings"""
    print_header("1. CHECKING SMS CONFIGURATION")
    
    # Check for ARKE SEL configuration
    arkesel_base_url = getattr(settings, 'ARKESEL_BASE_URL', None)
    arkesel_api_key = getattr(settings, 'ARKESEL_API_KEY', None)
    arkesel_sender_id = getattr(settings, 'ARKESEL_SENDER_ID', None)
    
    if arkesel_base_url:
        print_info(f"ARKE SEL Base URL: {arkesel_base_url}")
    else:
        print_warning("ARKESEL_BASE_URL not configured")
    
    if arkesel_api_key:
        # Mask the API key for security
        masked_key = arkesel_api_key[:8] + "..." + arkesel_api_key[-4:] if len(arkesel_api_key) > 12 else "***"
        print_info(f"ARKE SEL API Key: {masked_key}")
    else:
        print_warning("ARKESEL_API_KEY not configured")
    
    if arkesel_sender_id:
        print_info(f"ARKE SEL Sender ID: {arkesel_sender_id}")
    else:
        print_warning("ARKESEL_SENDER_ID not configured")
    
    # Check if SMS is enabled
    sms_enabled = getattr(settings, 'SMS_ENABLED', True)
    print_info(f"SMS Enabled: {sms_enabled}")
    
    # Also check for other SMS configs
    sms_backend = getattr(settings, 'SMS_BACKEND', None)
    if sms_backend:
        print_info(f"SMS Backend: {sms_backend}")
    
    return arkesel_base_url and arkesel_api_key

def check_users_with_phone_numbers():
    """Check users that have phone numbers"""
    print_header("2. CHECKING USERS WITH PHONE NUMBERS")
    
    users = User.objects.all()
    
    users_with_phone = []
    users_without_phone = []
    
    for user in users:
        # Try common phone field names
        phone = None
        for field in ['phone', 'phone_number', 'mobile', 'mobile_number', 'phone_no']:
            if hasattr(user, field):
                phone = getattr(user, field)
                if phone:
                    break
        
        if phone:
            users_with_phone.append((user, phone))
        else:
            users_without_phone.append(user)
    
    print_info(f"Total users: {len(users)}")
    print_info(f"Users with phone numbers: {len(users_with_phone)}")
    print_info(f"Users without phone numbers: {len(users_without_phone)}")
    
    if users_with_phone:
        print_subheader("Users with phone numbers:")
        for user, phone in users_with_phone:
            print(f"  • {user.email} -> {phone}")
    
    return users_with_phone

def create_sms_campaign(users_with_phone):
    """Create an SMS campaign"""
    print_header("3. CREATING SMS CAMPAIGN")
    
    if not users_with_phone:
        print_error("No users with phone numbers found")
        return None
    
    try:
        # Get a creator user
        creator = User.objects.filter(is_staff=True).first() or User.objects.first()
        
        # Get recipients (users with phone numbers)
        recipients = [user for user, phone in users_with_phone]
        
        if not recipients:
            print_error("No recipients available")
            return None
        
        print_info(f"Creator: {creator.email}")
        print_info(f"Recipients ({len(recipients)}):")
        for user, phone in users_with_phone:
            print_sms(f"    - {user.email} ({phone})")
        
        # Create campaign data
        timestamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        campaign_data = {
            'name': f'SMS Campaign {timestamp}',
            'subject': f'SMS Alert - {timestamp}',
            'message': f'Test SMS message sent at {timestamp}. This is a test of the ARKE SEL SMS notification system.',
            'channel': 'sms',
            'is_scheduled': False,
        }
        
        print_info("Creating SMS campaign...")
        
        # Create campaign using service
        service = NotificationService()
        campaign = service.create_campaign(
            data=campaign_data,
            created_by=creator,
            recipient_users=recipients,
            org_slug=getattr(creator, 'org_slug', 'default')
        )
        
        print_success(f"SMS Campaign created successfully!")
        print_info(f"  Campaign ID: {campaign.id}")
        print_info(f"  Campaign Name: {campaign.name}")
        print_info(f"  Channel: {campaign.channel}")
        
        # Verify notifications were created
        notifications = Notification.objects.filter(campaign=campaign)
        pending = notifications.filter(status='pending')
        
        print_info(f"  Notifications created: {notifications.count()}")
        print_info(f"  Pending SMS notifications: {pending.count()}")
        
        if pending.count() > 0:
            print_success("✓ SMS notifications successfully created")
            
            # Show notification details
            print_subheader("SMS Notification Details")
            for n in pending:
                print_sms(f"  To: {n.recipient_address}")
                print(f"     Status: {n.status}")
                print(f"     Message: {n.message[:50]}...")
                print()
        else:
            print_warning("No pending SMS notifications were created!")
        
        return campaign
        
    except Exception as e:
        print_error(f"Failed to create SMS campaign: {e}")
        import traceback
        traceback.print_exc()
        return None

def dispatch_sms_task(campaign):
    """Dispatch Celery task for SMS campaign"""
    print_header("4. DISPATCHING SMS TASKS")
    
    if not campaign:
        print_error("No campaign provided")
        return None
    
    try:
        print_sms(f"Dispatching task for SMS campaign #{campaign.id} - {campaign.name}")
        
        # Verify Celery connection before dispatching
        from hms.celery import app
        print_info(f"Using broker: {app.conf.broker_url}")
        
        # Test connection first
        try:
            conn = app.connection()
            conn.connect()
            print_success("Celery connection successful")
            conn.release()
        except Exception as e:
            print_error(f"Celery connection failed: {e}")
            return None
        
        # Dispatch the task
        result = dispatch_campaign_task.delay(campaign.id)
        
        print_success(f"SMS task dispatched successfully!")
        print_info(f"  Task ID: {result.id}")
        print_info(f"  Task State: {result.state}")
        
        return result
        
    except Exception as e:
        print_error(f"Failed to dispatch SMS task: {e}")
        import traceback
        traceback.print_exc()
        return None

def monitor_sms_task(task_result, campaign_id, timeout=60):
    """Monitor SMS task progress"""
    print_header("5. MONITORING SMS TASK PROGRESS")
    
    if not task_result:
        print_error("No task to monitor")
        return False
    
    print_info(f"Waiting for SMS task to complete (timeout: {timeout} seconds)...")
    print_info("SMS sending may take a few moments")
    print_info("Check Celery worker terminal for detailed logs")
    
    start_time = time.time()
    dots = 0
    
    while time.time() - start_time < timeout:
        if task_result.ready():
            elapsed = time.time() - start_time
            print(f"\n{Colors.GREEN}✓ SMS task completed in {elapsed:.2f} seconds{Colors.RESET}")
            
            # Check task result
            try:
                result = task_result.result
                if result:
                    print_info(f"Task result: {result}")
            except Exception as e:
                print_info(f"Task result not available: {e}")
            
            return True
        
        # Show progress animation
        elapsed = int(time.time() - start_time)
        dots = (elapsed % 3) + 1
        print(f"  Sending SMS... {'.' * dots}{' ' * (3 - dots)}\r", end='')
        time.sleep(1)
    
    print(f"\n{Colors.RED}✗ SMS task did not complete within {timeout} seconds{Colors.RESET}")
    print_info(f"Task ID: {task_result.id}")
    print_info("Check Celery worker logs for details")
    return False

def check_sms_results(campaign_id):
    """Check SMS campaign results"""
    print_header("6. CHECKING SMS RESULTS")
    
    try:
        campaign = Campaign.objects.get(id=campaign_id)
        notifications = Notification.objects.filter(campaign=campaign)
        
        print_subheader("SMS Campaign Status")
        print_sms(f"Campaign #{campaign.id}: {campaign.name}")
        print_info(f"  Channel: {campaign.channel}")
        print_info(f"  Is Sent: {campaign.is_sent}")
        if campaign.sent_at:
            print_info(f"  Sent At: {campaign.sent_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Notification statistics
        print_subheader("SMS Delivery Status")
        total = notifications.count()
        pending = notifications.filter(status='pending').count()
        sent = notifications.filter(status='sent').count()
        failed = notifications.filter(status='failed').count()
        
        print_info(f"Total SMS messages: {total}")
        
        if sent > 0:
            print_success(f"  ✓ Successfully sent: {sent}")
        if pending > 0:
            print_warning(f"  ⏳ Pending: {pending}")
        if failed > 0:
            print_error(f"  ✗ Failed: {failed}")
        
        # Show detailed SMS notifications
        if total > 0:
            print_subheader("SMS Delivery Details")
            for n in notifications:
                status_icon = "✓" if n.status == 'sent' else "⏳" if n.status == 'pending' else "✗"
                status_color = Colors.GREEN if n.status == 'sent' else Colors.YELLOW if n.status == 'pending' else Colors.RED
                
                print_sms(f"  {status_color}{status_icon} To: {n.recipient_address}{Colors.RESET}")
                print(f"     Status: {n.status}")
                if n.sent_at:
                    print(f"     Sent at: {n.sent_at}")
                if n.error_message:
                    print_error(f"     Error: {n.error_message}")
                print()
        
        return total, sent, failed, pending
        
    except Campaign.DoesNotExist:
        print_error(f"Campaign {campaign_id} not found")
        return 0, 0, 0, 0

def main():
    """Main SMS test function"""
    print_header("ARKE SEL SMS NOTIFICATION SYSTEM TEST")
    print_sms("Testing complete SMS notification workflow with ARKE SEL\n")
    
    # Step 0: Check Celery configuration
    if not check_celery_config():
        print_error("Celery configuration is incorrect. Cannot proceed.")
        print_info("Make sure CELERY_BROKER_URL is set to Redis in your .env file")
        return False
    
    # Step 1: Check SMS configuration
    sms_configured = check_sms_configuration()
    if not sms_configured:
        print_warning("\nSMS not fully configured. You need to configure ARKE SEL in your .env file:")
        print_info("  ARKESEL_BASE_URL=https://sms.arkesel.com/api")
        print_info("  ARKESEL_API_KEY=your_api_key")
        print_info("  ARKESEL_SENDER_ID=YourSenderID")
        print_info("  SMS_BACKEND=arkesel")
        return False
    
    # Step 2: Check users with phone numbers
    users_with_phone = check_users_with_phone_numbers()
    
    if not users_with_phone:
        print_error("No users with phone numbers found!")
        print_info("Please add phone numbers to users first")
        return False
    
    # Step 3: Create SMS campaign
    campaign = create_sms_campaign(users_with_phone)
    if not campaign:
        print_error("Failed to create SMS campaign")
        return False
    
    # Step 4: Dispatch SMS task
    task_result = dispatch_sms_task(campaign)
    if not task_result:
        print_error("Failed to dispatch SMS task")
        return False
    
    # Step 5: Monitor task
    monitor_sms_task(task_result, campaign.id, timeout=60)
    
    # Step 6: Check results
    time.sleep(3)  # Give a moment for async updates
    total, sent, failed, pending = check_sms_results(campaign.id)
    
    # Summary
    print_header("SMS TEST SUMMARY")
    if total > 0:
        if sent > 0:
            print_success(f"✓ {sent} SMS messages sent successfully!")
            print_success("✓ SMS notification system working correctly!")
        else:
            print_warning("⚠ SMS messages were queued but not delivered")
            
        if pending > 0:
            print_warning(f"⚠ {pending} SMS messages still pending")
            print_info("Check Celery worker logs for more details")
            
        if failed > 0:
            print_error(f"✗ {failed} SMS messages failed")
            print_info("Check error messages above for details")
    else:
        print_warning("No SMS messages were created")
    
    print_info(f"\nCampaign ID: {campaign.id}")
    print_info("You can check detailed SMS logs in:")
    print_info("  - Celery worker terminal")
    print_info("  - Django admin interface")
    print_info("  - Database notification records")
    
    return sent > 0 if total > 0 else False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSMS test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)