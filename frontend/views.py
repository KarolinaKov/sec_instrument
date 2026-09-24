from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, FileResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.conf import settings
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .create_live_ips import create_live_ips
from .models import Test
from .permissions import IsSenior, IsSeniorOrJunior, SENIOR_GROUP
from .serializers import TestSerializer
from datetime import datetime, date, time, timedelta
from pathlib import Path
from croniter import croniter
import calendar
import csv
import io
import zipfile


@ensure_csrf_cookie
@login_required
def home_view(request):
    """Render the home page with the main interface"""
    is_senior = request.user.is_superuser or request.user.groups.filter(name=SENIOR_GROUP).exists()
    return render(request, 'frontend/home.html', {'is_senior': is_senior})


class SubmitTest(APIView):
    """
    API endpoint to create a new test and trigger scan.
    Senior users only - juniors can view/download but not add tests.
    """
    permission_classes = [IsAuthenticated, IsSenior]
    
    def post(self, request):
        serializer = TestSerializer(data=request.data)
        if serializer.is_valid():
            try:
                data = serializer.validated_data
                test_object = Test.objects.create(
                    ip_address=data['ip_address'], 
                    prefix=data['prefix'], 
                    hostname=data.get('hostname', ''),
                    nickname=data['nickname'], 
                    cron=data['cron'], 
                    created_by=request.user
                )
                
                create_live_ips(str(data['ip_address']), str(data['prefix']), test_object)
                
                response_serializer = TestSerializer(test_object)
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling Test read, delete operations and downloads.

    Both senior and junior users can list/view/download tests; only
    seniors can delete them (adding is handled separately by SubmitTest,
    also senior-only).
    """
    queryset = Test.objects.all()
    serializer_class = TestSerializer
    http_method_names = ['get', 'patch', 'delete']

    def partial_update(self, request, *args, **kwargs):
        if 'cron' in request.data:
            cron_expression = str(request.data['cron']).strip()
            if len(cron_expression.split()) != 5:
                return Response(
                    {'cron': 'Use exactly five cron fields: minute hour day month weekday.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                croniter(cron_expression, timezone.now())
            except (TypeError, ValueError):
                return Response(
                    {'cron': 'Enter a valid five-field cron expression.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        response = super().partial_update(request, *args, **kwargs)
        if response.status_code < 300 and 'cron' in request.data:
            test = self.get_object()
            if test.cron_is_active:
                from backend.scheduler import enable_scan_schedule
                enable_scan_schedule(test)
                response.data = TestSerializer(test).data
        return response

    def get_permissions(self):
        if self.action in ('destroy', 'partial_update', 'alert_settings', 'schedule_settings'):
            permission_classes = [IsAuthenticated, IsSenior]
        else:
            permission_classes = [IsAuthenticated, IsSeniorOrJunior]
        return [permission_class() for permission_class in permission_classes]

    @action(detail=True, methods=['patch'], url_path='alert-settings')
    def alert_settings(self, request, pk=None):
        """Enable or disable new-vulnerability-only alerts for one test."""
        test = self.get_object()
        enabled = request.data.get('enabled')
        if not isinstance(enabled, bool):
            return Response(
                {'error': 'enabled must be a boolean'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from backend.models import LogScan

        if enabled:
            latest_scan = LogScan.objects.filter(
                test=test,
                status='completed'
            ).order_by('-id').first()
            test.new_vulnerability_alerts_enabled = True
            test.new_vulnerability_alerts_since = timezone.now()
            test.new_vulnerability_alerts_log_scan_id = latest_scan.id if latest_scan else None
        else:
            test.new_vulnerability_alerts_enabled = False
            test.new_vulnerability_alerts_since = None
            test.new_vulnerability_alerts_log_scan_id = None

        test.save(update_fields=[
            'new_vulnerability_alerts_enabled',
            'new_vulnerability_alerts_since',
            'new_vulnerability_alerts_log_scan_id'
        ])
        return Response(TestSerializer(test).data)

    @action(detail=True, methods=['patch'], url_path='schedule-settings')
    def schedule_settings(self, request, pk=None):
        """Activate or deactivate the recurring scan schedule for one test."""
        test = self.get_object()
        enabled = request.data.get('enabled')
        if not isinstance(enabled, bool):
            return Response(
                {'error': 'enabled must be a boolean'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from backend.scheduler import disable_scan_schedule, enable_scan_schedule

            if enabled:
                enable_scan_schedule(test)
            else:
                disable_scan_schedule(test)
        except Exception as error:
            return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(TestSerializer(test).data)

    @action(detail=False, methods=['get'])
    def monthly_schedule(self, request):
        """Return daily and hourly schedule counts for a requested month."""
        today = timezone.localdate()
        try:
            year = int(request.query_params.get('year', today.year))
            month = int(request.query_params.get('month', today.month))
            month_date = date(year, month, 1)
        except (TypeError, ValueError):
            return Response(
                {'error': 'year and month must define a valid month'},
                status=status.HTTP_400_BAD_REQUEST
            )

        days_in_month = calendar.monthrange(year, month)[1]
        month_start = datetime.combine(month_date, time.min)
        month_end = month_start + timedelta(days=days_in_month)
        daily_counts = {day: 0 for day in range(1, days_in_month + 1)}
        hourly_counts = {
            day: {hour: {'count': 0, 'tests': set()} for hour in range(24)}
            for day in range(1, days_in_month + 1)
        }

        for test in self.get_queryset().filter(cron_is_active=True):
            try:
                schedule = croniter(
                    test.cron,
                    month_start - timedelta(minutes=1)
                )
                occurrence = schedule.get_next(datetime)
                while occurrence < month_end:
                    day = occurrence.day
                    hour = occurrence.hour
                    daily_counts[day] += 1
                    hourly_counts[day][hour]['count'] += 1
                    hourly_counts[day][hour]['tests'].add(
                        f'{test.nickname} (#{test.id})'
                    )
                    occurrence = schedule.get_next(datetime)
            except (ValueError, KeyError, TypeError):
                continue

        from backend.models import LogScanRetry

        month_start_aware = timezone.make_aware(month_start)
        month_end_aware = timezone.make_aware(month_end)
        retries = LogScanRetry.objects.filter(
            scheduled_for__gte=month_start_aware,
            scheduled_for__lt=month_end_aware
        ).select_related('log_scan__test')

        for retry in retries:
            scheduled_at = timezone.localtime(retry.scheduled_for)
            day = scheduled_at.day
            hour = scheduled_at.hour
            test = retry.log_scan.test
            label = f'Retry: {test.nickname} (#{test.id})'
            daily_counts[day] += 1
            hourly_counts[day][hour]['count'] += 1
            hourly_counts[day][hour]['tests'].add(label)

        days = []
        for day in range(1, days_in_month + 1):
            hours = [
                {
                    'hour': hour,
                    'count': hourly_counts[day][hour]['count'],
                    'tests': sorted(hourly_counts[day][hour]['tests'])
                }
                for hour in range(24)
                if hourly_counts[day][hour]['count']
            ]
            days.append({
                'day': day,
                'weekday': date(year, month, day).weekday(),
                'count': daily_counts[day],
                'hours': hours
            })

        return Response({
            'year': year,
            'month': month,
            'month_name': month_date.strftime('%B %Y'),
            'days': days
        })


    @action(detail=False, methods=['get'])
    def download_data(self, request):
        """
        Download test data within a date range
        Query params: from_date, until_date
        """
        from_date = request.query_params.get('from_date')
        until_date = request.query_params.get('until_date')
        
        if not from_date or not until_date:
            return Response(
                {'error': 'Both from_date and until_date are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            from_date = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            until_date = datetime.fromisoformat(until_date.replace('Z', '+00:00'))
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        tests = self.get_queryset().filter(
            when_added__gte=from_date,
            when_added__lte=until_date
        )
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'ID', 'IP Address', 'Prefix', 'Nickname', 'Cron',
            'Last Test', 'Next Scheduled', 'When Added', 'Status', 'Live IPs Count'
        ])
        
        for test in tests:
            live_ip_count = len(test.ip_current.ip_address) if test.ip_current else 0
            writer.writerow([
                test.id,
                test.ip_address,
                test.prefix,
                test.nickname,
                test.cron,
                test.last_test,
                test.next_scheduled,
                test.when_added,
                test.status,
                live_ip_count
            ])
        
        output.seek(0)
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="tests_{from_date.date()}_to_{until_date.date()}.csv"'
        
        return response
    
    @action(detail=True, methods=['get'])
    def download_single(self, request, pk=None):
        """
        Download a single test's data as CSV including live IPs
        """
        test = self.get_object()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'ID', 'IP Address', 'Prefix', 'Nickname', 'Cron',
            'Last Test', 'Next Scheduled', 'When Added', 'Status'
        ])
        
        writer.writerow([
            test.id,
            test.ip_address,
            test.prefix,
            test.nickname,
            test.cron,
            test.last_test,
            test.next_scheduled,
            test.when_added,
            test.status
        ])
        
        if test.ip_current and test.ip_current.ip_address:
            writer.writerow([])
            writer.writerow(['Live IPs Found:'])
            for ip in test.ip_current.ip_address:
                writer.writerow([ip])

        output.seek(0)
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="test_{test.id}_{test.nickname}.csv"'

        return response

    @action(detail=False, methods=['get'])
    def download_scan_outputs(self, request):
        """
        Zip scan output folders whose dates fall within [from_date, until_date].
        When id is supplied, include only the output folder ending in _<id>.
        Query params: from_date, until_date (YYYY-MM-DD), optional id
        """
        from_date_str = request.query_params.get('from_date')
        until_date_str = request.query_params.get('until_date')
        test_id = request.query_params.get('id', '').strip()

        if test_id and not test_id.isdigit():
            return Response(
                {'error': 'id must contain only digits'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not from_date_str or not until_date_str:
            return Response(
                {'error': 'Both from_date and until_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from_date = date.fromisoformat(from_date_str)
            until_date = date.fromisoformat(until_date_str)
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use YYYY-MM-DD'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if from_date > until_date:
            return Response(
                {'error': 'from_date must be on or before until_date'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scan_outputs_root = Path(settings.BASE_DIR) / 'scan_outputs'

        buffer = io.BytesIO()
        found_any = False
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            if scan_outputs_root.exists():
                for date_dir in sorted(scan_outputs_root.iterdir()):
                    if not date_dir.is_dir():
                        continue
                    try:
                        folder_date = date.fromisoformat(date_dir.name)
                    except ValueError:
                        continue
                    if not (from_date <= folder_date <= until_date):
                        continue

                    output_dirs = [date_dir]
                    if test_id:
                        output_dirs = [
                            output_dir for output_dir in date_dir.iterdir()
                            if output_dir.is_dir() and output_dir.name.rsplit('_', 1)[-1] == test_id
                        ]

                    if not output_dirs:
                        continue

                    found_any = True
                    for output_dir in output_dirs:
                        for file_path in output_dir.rglob('*'):
                            if not file_path.is_file():
                                continue
                            arcname = file_path.relative_to(scan_outputs_root)
                            zf.write(file_path, arcname)

        if not found_any:
            return Response(
                {'error': 'No scan output folders found for that date range and ID'},
                status=status.HTTP_404_NOT_FOUND
            )

        buffer.seek(0)
        id_suffix = f"-{test_id}" if test_id else ""
        filename = f"{from_date.isoformat()}-{until_date.isoformat()}{id_suffix}.zip"
        response = HttpResponse(buffer.getvalue(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    @action(detail=True, methods=['get'])
    def download_last_scan(self, request, pk=None):
        """
        Download the most recent scan's comprehensive result file for this
        test, as-is (not zipped).
        """
        from backend.models import LogScan

        test = self.get_object()

        log_scan = LogScan.objects.filter(test=test).order_by('-timestamp_start').first()
        if not log_scan or not log_scan.path_to_file:
            return Response(
                {'error': 'No scan results found for this test'},
                status=status.HTTP_404_NOT_FOUND
            )

        file_path = Path(log_scan.path_to_file)
        if not file_path.exists():
            return Response(
                {'error': 'Scan result file is missing on disk'},
                status=status.HTTP_404_NOT_FOUND
            )

        return FileResponse(
            open(file_path, 'rb'),
            as_attachment=True,
            filename=file_path.name,
            content_type='application/json',
        )