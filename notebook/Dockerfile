FROM jupyter/minimal-notebook:latest

USER jovyan

RUN conda install -y matplotlib==1.5.0 \
    numpy==1.10.2 \
    pandas==0.17.1 \
    scipy==0.16.1 \
    seaborn==0.6.0 \
    ipywidgets

RUN conda install -y -c http://use.yt/with_conda/ yt
RUN pip install girder-client

COPY auth/by_volume.py \
    /opt/conda/lib/python3.5/site-packages/notebook/auth/
COPY templates/login_register.html \
    /opt/conda/lib/python3.5/site-packages/notebook/templates

RUN pip install jupyter_cms==0.2.1

USER root
