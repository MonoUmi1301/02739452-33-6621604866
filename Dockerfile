# ใช้ Apache Airflow เป็น Base Image
FROM apache/airflow:2.10.5-python3.11

# กำหนด Working Directory
WORKDIR /opt/airflow

# คัดลอกรายการ Python Libraries
COPY requirements.txt /requirements.txt

# ติดตั้ง Dependencies
RUN pip install --no-cache-dir -r /requirements.txt

# คัดลอกโค้ด Dashboard
COPY web/ /opt/airflow/web/

# กำหนด Python Module Path
ENV PYTHONPATH="/opt/airflow/web:/opt/airflow/dags/include"

# ใช้ User airflow ตามแนวทางของ Official Image
USER airflow