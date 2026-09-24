from rest_framework import serializers
from .models import Test
from .dns_utils import resolve_hostname_ips
from ipaddress import ip_network


class TestSerializer(serializers.ModelSerializer):
    ip_address = serializers.IPAddressField(required=False)
    prefix = serializers.IntegerField(required=False)
    hostname = serializers.CharField(required=False, allow_blank=True)
    nickname = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Test
        fields = ['id', 'ip_address', 'prefix', 'hostname', 'nickname', 'cron', 'last_test',
                  'next_scheduled', 'when_added', 'cron_is_active',
                  'new_vulnerability_alerts_enabled', 'new_vulnerability_alerts_since',
                  'new_vulnerability_alerts_log_scan_id']
        read_only_fields = ['id', 'when_added', 'last_test', 'next_scheduled']
    
    def validate(self, data):
        if self.instance and self.partial and not any(
            field in data for field in ('ip_address', 'prefix', 'hostname')
        ):
            return data

        hostname = data.get('hostname', '').strip()
        ip_address = data.get('ip_address')
        prefix = data.get('prefix')
        nickname_source = hostname or str(ip_address) if hostname or ip_address is not None else ''

        if hostname and (ip_address is not None or prefix is not None):
            raise serializers.ValidationError(
                'Provide either a DNS hostname or an IP address and prefix, not both.'
            )

        if hostname:
            resolved_ips = resolve_hostname_ips(hostname)
            if not resolved_ips:
                raise serializers.ValidationError(
                    {'hostname': 'The hostname could not be resolved.'}
                )
            data['hostname'] = hostname
            data['ip_address'] = resolved_ips[0]
            data['prefix'] = 32
        elif ip_address is None or prefix is None:
            raise serializers.ValidationError(
                'Provide either a DNS hostname or both an IP address and prefix.'
            )
        else:
            try:
                network = ip_network(f'{ip_address}/{prefix}', strict=False)
            except ValueError as error:
                raise serializers.ValidationError({'prefix': str(error)})
            data['ip_address'] = str(network.network_address)
            data['prefix'] = network.prefixlen

        if not data.get('nickname'):
            data['nickname'] = nickname_source
        return data