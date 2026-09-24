from django.apps import AppConfig


class BackendConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'backend'
    
    def ready(self):
        """
        Import application signals and task definitions when app is ready.
        """
        import backend.signals

        import backend.backend_tasks_kali

        try:
            from sec_instrument.celery import app as celery_app
            with celery_app.connection_or_acquire() as conn:
                celery_app.amqp.queues['celery'](conn).declare()
        except Exception as e:
            print(f"Error declaring Celery queue: {e}")