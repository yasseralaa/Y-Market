Y-Market
=============

**Description**

    - A basic market catalog storing user, supermarkets and it's products.
    - Made with python on flask and sqlalchemy.
    - Login, logout and registration forms with validation.
    - Authenticating using Facebook and google providers.
    - Users can view all supermarkets and it's all products.
    - Add, Edit and delete markets by authorized authors.
    - Add, Edit and delete products by authorized authors.
    - Api end points representing JSON data for all markets and products.
    - Using vagrant with ubuntu-trusty-32 and VirtualBox
    
**Features**
    
    - Written in python
    - Using flask framework
    - Sqlalchemy sqlite database
    - Bootstrap style
    
**Installation**

    - Download and install vagrant : https://www.vagrantup.com/downloads.html
    - Download and install https://www.virtualbox.org
    - Download or clone project from this dir
    - Open cmd or git bash
    - Go to project directory '/vagrant'
    - Run `vagrant up`
    - Then `vagrant ssh`
    - You are on ubuntu now, `cd /vagrant/catalog`
    - Run `python database_setup.py`
    - Then `python supermarket.py`
    - From any browser open : 'localhost:5000'
    - Enjoy :)
    
**Libraries and frameworks**

    - Flask framework : http://flask.pocoo.org/
    - sqlalchemy : https://www.sqlalchemy.org
    - oauth2client : https://pypi.python.org/pypi/oauth2client
    - jinja2 : http://jinja.pocoo.org
    - json : https://docs.python.org/2/library/json.html
    - os : https://docs.python.org/2/library/os.html
    - re : https://docs.python.org/2/library/re.html
    
**Contacts**

    - E-Mail: yasser.alaaeldin1995@gmail.com

**License**

MIT
