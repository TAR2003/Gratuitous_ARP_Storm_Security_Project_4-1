this monitor main file scans all the logs and results to determine the logs and show them to user by an UI. API endpoijts are there for programmatics access to logs and statistics 
Background data updatesd via a dedicated trhreasd
Visualtization of attack k status, container health and logs 

Here the main class is the web monitior class object, 
It manages the logs, attack status and container statuses with results
When montior start monitoritng is called in main 
it sets self,running  true and start the ipdate data in a backgorund thread 
Continuous data update, 
It runs ain  aloop for wevery 5 seocnds 
loads logs reads log file form app/logs
and parse  JSON entires keeps the last 100 logs 
