from django.core.management.base import BaseCommand
import subprocess

class Command(BaseCommand):
    help = "Automatically trains the model by running Classifier.py"

    def handle(self, *args, **kwargs):
        try:
            # Classifier.py রান করুন
            subprocess.run(["python", "Classifier.py"], check=True)
            self.stdout.write(self.style.SUCCESS("Model trained successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error: {e}"))