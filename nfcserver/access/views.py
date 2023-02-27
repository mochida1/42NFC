import zmq
from django.http import HttpResponse
from .models import Record
from django.shortcuts import render
from django_tables2 import Table, TemplateColumn
from datetime import datetime, timedelta
from django.conf import settings

def receive_message(request):
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    try:
        socket.bind(settings.ZEROMQ_SERVER_TCP)
    except Exception as e:
        print("Error binding socket:", e)

    message = socket.recv_string()
    socket.send_string("Message received")
    socket.close()
    parts = message.split()
    login = parts[0]
    is_entry = int(parts[1])
    timestamp = int(parts[2])
    record = Record(login=login, is_entry=is_entry, timestamp=timestamp)
    record.save()
    return HttpResponse('Message received')

class ReportTable(Table):
    login = ('Login')
    entry_time = TemplateColumn('Entry Time')
    exit_time = TemplateColumn('Exit Time')
    total_hours = TemplateColumn('Total Hours')

def generate_report(request):
    today = datetime.now()
    start_date = today - timedelta(days=today.weekday())
    end_date = start_date + timedelta(days=6)
    records = Record.objects.filter(timestamp__range=(start_date, end_date)).order_by('timestamp')
    report = {}
    for record in records:
        login = record.login
        is_entry = record.is_entry
        timestamp = record.timestamp
        if login not in report:
            report[login] = {'entry_time': None, 'exit_time': None, 'total_hours': 0}
        if is_entry == 1:
            report[login]['entry_time'] = timestamp
        elif is_entry == 0:
            if report[login]['entry_time']:
                hours = (timestamp - report[login]['entry_time']).total_seconds() / 3600
                report[login]['total_hours'] += hours
                report[login]['exit_time'] = timestamp
                report[login]['entry_time'] = None

    table_data = []
    for login, data in report.items():
        table_data.append({'login': login,
                           'entry_time': data['entry_time'],
                           'exit_time': data['exit_time'],
                           'total_hours': data['total_hours']})

    report_table = ReportTable(table_data)
    return render(request, 'report.html', {'report_table': report_table})
