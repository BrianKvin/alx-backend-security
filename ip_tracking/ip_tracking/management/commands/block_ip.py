from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    help = 'Add IP addresses to the blacklist'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address',
            default='Manual block'
        )
        parser.add_argument(
            '--unblock',
            action='store_true',
            help='Remove IP address from blacklist'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options['reason']
        unblock = options['unblock']

        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise CommandError(f'Invalid IP address format: {ip_address}')

        if unblock:
            # Remove from blacklist
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
                blocked_ip.delete()
                
                # Clear cache
                cache_key = f"blocked_ip_{ip_address}"
                cache.delete(cache_key)
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
                )
            except BlockedIP.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} was not in the blacklist')
                )
        else:
            # Add to blacklist
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason}
            )
            
            if created:
                # Clear cache to ensure immediate effect
                cache_key = f"blocked_ip_{ip_address}"
                cache.set(cache_key, True, 300)
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully blocked IP: {ip_address} (Reason: {reason})'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} is already blocked')
                )