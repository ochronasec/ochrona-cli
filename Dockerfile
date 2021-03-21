FROM python:3.9.2-slim-buster
RUN pip install --trusted-host pypi.python.org ochrona
CMD ["python"]