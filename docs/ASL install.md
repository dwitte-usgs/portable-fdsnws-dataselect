# The portable-fdsnws-dataselect ASL
 
## Build and Install

* Log into target server: ```ssh vmdevwb```  
* Set user as asluser for services: ```sudo su asluser```
* Set location: ```cd /data/www/```
* Clone Repo: ```git Clone git@github.com:dwitte-usgs/portable-fdsnws-dataselect.git```  
* Set branch to devel: ```git checkout devel```  
* Create virtual environment: ```python3 -m venv venv```
* Start virtual environment: ```source venv/bin/activate```
* Build portable-fdsnws-dataselect module and install it in virtual environment.  
Creates portable_fdsnws_dataselect directory in venv python site-packages and portable_fdsnws_dataselect-1.1.6-py3.4.egg-info  
/data/www/portable-fdsnws-dataselect/venv/lib/python3.4/site-packages/portable_fdsnws_dataselect  
Creates service script in /data/www/portable-fdsnws-dataselect/venv/portable-fdsnws-dataselect  
```python3 setup.py install```
* Copy server.ini from portable-fdsnws-dataselect/example into portable-fdsnws-dataselect root directory and edit
  * Add DB parameters if using SQLite or Postgres
  * Comment out summary_table (currently unused)
  * Comment out logging unless debugging
* Load PYTHON modules from requirements.txt into virtual environment  
```pip3 install -r requirements.txt```

## Test locally
* Run server starter file portable-fdsnws-dataselect passing in .ini file  
```/data/www/portable-fdsnws-dataselect/venv/bin/portable-fdsnws-dataselect /data/www/portable-fdsnws-dataselect/server.ini```  
This URL should give you a help page (note Port=8080): ```http://vmdevwb:8080/fdsnws/dataselect/1```

## Make a daemon

* sudo as root, systemd is all under root
* Go to systemd directory ```cd /usr/lib/systemd/system/```
* Create a service file  
```portable-fdsnws-dataselect.service```  
containing the following

```
[Unit]
Description=portable fdsnws dataselect service for mseed files
 
[Service]
ExecStart=/data/www/portable-fdsnws-dataselect/venv/bin/portable-fdsnws-dataselect /data/www/portable-fdsnws-dataselect/server.ini
```

* Load service into systemd system  
```systemctl daemon-reload```                                                            
* Start service  
```systemctl start portable-fdsnws-dataselect.service```
* Stop service  
```systemctl stop portable-fdsnws-dataselect.service```
* Service status  
```systemctl status portable-fdsnws-dataselect.service```
