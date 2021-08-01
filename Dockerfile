FROM python:3.9.6-slim-buster
RUN pip install --trusted-host pypi.python.org ochrona
CMD ["python"]