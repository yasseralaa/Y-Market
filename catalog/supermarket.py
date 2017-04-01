import json
import os
import random
import string
import httplib2
import requests
from flask import Flask, render_template, request, redirect, jsonify
from flask import make_response, url_for, flash
from flask import session as login_session
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug import secure_filename

from database_setup import Base, Supermarket, Products, User

# general variables
app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "supermarkets app"
engine = create_engine('sqlite:///supermarket.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


# root function
@app.route('/')
@app.route('/markets')
def Home():
    supermarket = session.query(Supermarket).first()
    supermarkets = session.query(Supermarket).all()
    user = session.query(User).all()
    if supermarket:
        products = session.query(Products).filter_by(
            supermarket_id=supermarket.id)
    else:
        products = [""]
    loggedin = 'name' in login_session
    if loggedin:
        currentUser = login_session['name']
    else:
        currentUser = ""
    return render_template(
        'home.html',
        supermarkets=supermarkets,
        supermarket=supermarket,
        products=products,
        currentUser=currentUser,
        loggedin=loggedin)


# end point function representing specific supermarket and all it's products
@app.route('/market/<int:supermarket_id>/product/JSON')
def marketProductJSON(supermarket_id):
    products = session.query(Products).filter_by(
        supermarket_id=supermarket_id).all()
    return jsonify(Products=[i.serialize for i in products])


# end point function representing specific all supermarkets
@app.route('/markets/JSON')
def marketsJSON():
    supermarket = session.query(Supermarket).all()
    return jsonify(Supermarket=[i.serialize for i in supermarket])


# Authentication part

# helper methods
def createUser(login_session):
    if login_session['provider'] == 'local':
        newUser = User(
            name=login_session['name'],
            password=login_session['password'],
            email=login_session['email'],
            picture=login_session['picture'])
    else:
        newUser = User(name=login_session['name'], email=login_session[
            'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user.id
    except BaseException:
        return None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# local Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'name' in login_session:
        flash('You are already member')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        if 'name' in login_session:
            loggedin = 'name' in login_session
            return redirect(url_for('Home', loggedin=loggedin))
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        checkexisting = session.query(User).filter_by(
            email=request.form['email']).first()
        if checkexisting is not None:
            flash('This E-Mail registered before, login with it')
            return redirect(url_for('login'))
        checkexisting = session.query(User).filter_by(
            name=request.form['name']).first()
        if checkexisting is not None:
            flash('This name registered before')
            return redirect(url_for('login'))
        if request.form['password'] != request.form['repassword']:
            flash('passwords is not matches')
            return redirect(url_for('login'))
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        login_session['name'] = request.form['name']
        login_session['email'] = request.form['email']
        login_session['picture'] = filename
        login_session['provider'] = 'local'
        login_session['password'] = request.form['password']
        createUser(login_session)
        flash('New User %s Successfully Created' % login_session['name'])
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        # return "The current session state is %s" % login_session['state']
        return render_template('login.html', STATE=state)


# local Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'name' in login_session:
        flash('You are already member')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        user = session.query(User).filter_by(
            email=request.form['email'],
            password=request.form['password']).first()
        if user is None:
            flash('Wrong email or password')
            return redirect(url_for('login'))
        login_session['name'] = user.name
        login_session['email'] = user.email
        login_session['picture'] = user.picture
        login_session['provider'] = 'local'
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        # return "The current session state is %s" % login_session['state']
        return render_template('login.html', STATE=state)


# authentication using google api
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    flash('User %s logged in Successfully' % data['name'])
    login_session['name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'
    createUser(login_session)
    loggedin = 'name' in login_session
    return redirect(url_for('Home', loggedin=loggedin))


@app.route('/gdisconnect')
def gdisconnect():
    if 'provider' not in login_session \
            or login_session['provider'] != 'google':
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))

    access_token = login_session['access_token']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        flash('User %s loggedout Successfully' % login_session['name'])
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['name']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        # return response
        loggedin = 'name' in login_session
        return redirect(url_for('login', loggedin=loggedin))
    else:

        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400))
        response.headers['Content-Type'] = 'application/json'
    flash(response)
    loggedin = 'name' in login_session
    return redirect(url_for('login', loggedin=loggedin))


# authentication using facebook api
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.8/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API.
    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['name'] = str(data['name'])
    login_session['email'] = str(data['email'])
    login_session['facebook_id'] = str(data['id'])

    # The token must be stored in the login_session in order to properly
    # logout, let's strip out the information before the equals sign in our
    # token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture' \
          '?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    createUser(login_session)
    loggedin = 'name' in login_session
    return redirect(url_for('Home', loggedin=loggedin))


@app.route('/fbdisconnect')
def fbdisconnect():
    if 'provider' not in login_session \
            or login_session['provider'] != 'facebook':
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))

    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    login_session.clear()
    loggedin = False
    return redirect(url_for('Home', loggedin=loggedin))


# logout for all providers
@app.route('/logout')
def logout():
    if 'provider' in login_session and login_session['provider'] == 'facebook':
        return fbdisconnect()

    if 'provider' in login_session and login_session['provider'] == 'google':
        return gdisconnect()

    if 'provider' not in login_session or login_session['provider'] != 'local':
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    flash('User %s logged out Successfully' % login_session['name'])
    login_session.clear()
    loggedin = False
    return redirect(url_for('Home', loggedin=loggedin))


# Application elements area

# Viewing supermarket
@app.route('/market/<int:supermarket_id>/')
def market(supermarket_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    products = session.query(Products).filter_by(supermarket_id=supermarket.id)
    loggedin = 'name' in login_session
    if loggedin:
        currentUser = login_session['name']
    else:
        currentUser = ""
    return render_template(
        'market.html',
        currentUser=currentUser,
        loggedin=loggedin,
        supermarket=supermarket,
        products=products)


# Add supermarket
@app.route('/addmarket', methods=['GET', 'POST'])
def addmarket():
    if 'name' not in login_session:
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        if 'name' not in login_session:
            loggedin = 'name' in login_session
            return redirect(url_for('Home', loggedin=loggedin))
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        checkexisting = session.query(Supermarket).filter_by(
            name=request.form['name']).first()
        if checkexisting is not None:
            flash('This Supermarket Inserted before')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        newMarket = Supermarket(
            name=request.form['name'],
            address=request.form['address'],
            user_id=getUserID(
                login_session['email']),
            picture=filename)

        session.add(newMarket)
        session.commit()
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    else:
        loggedin = 'name' in login_session
        return render_template('addmarket.html', loggedin=loggedin)


# Edit supermarket
@app.route('/editmarket/<int:supermarket_id>/', methods=['GET', 'POST'])
def editmarket(supermarket_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    if 'name' not in login_session \
            or supermarket is None \
            or supermarket.user.name != login_session['name']:
        flash('You are not authorized to edit this market')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        if 'name' not in login_session:
            loggedin = 'name' in login_session
            return redirect(url_for('Home', loggedin=loggedin))
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        oldValues = session.query(Supermarket).filter_by(
            name=supermarket.name).first()
        checkexisting = session.query(Supermarket).filter_by(
            name=request.form['name']).first()
        if checkexisting and checkexisting.id is not supermarket.id:
            flash('There is a previous Supermarket used this name')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            filename = oldValues.picture
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        oldValues.name = request.form['name']
        oldValues.address = request.form['address']
        oldValues.picture = filename

        session.commit()
        loggedin = 'name' in login_session
        return redirect(
            url_for(
                'market',
                supermarket_id=supermarket.id,
                loggedin=loggedin))
    else:
        loggedin = 'name' in login_session
        return render_template(
            'editmarket.html',
            supermarket=supermarket,
            loggedin=loggedin)


# Delete supermarket
@app.route('/deletemarket/<int:supermarket_id>/', methods=['GET', 'POST'])
def deletemarket(supermarket_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    if 'name' not in login_session \
            or supermarket is None \
            or supermarket.user.name != login_session['name']:
        flash('You are not authorized to delete this market')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    session.query(Products).filter_by(supermarket_id=supermarket.id).delete()
    session.query(Supermarket).filter_by(id=supermarket.id).delete()
    flash('market and inner products has been deleted')
    return redirect(url_for('Home'))


# Viewing product
@app.route('/product/<int:supermarket_id>/<int:product_id>/')
def product(supermarket_id, product_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    product = session.query(Products).filter_by(id=product_id).first()
    loggedin = 'name' in login_session
    if loggedin:
        currentUser = login_session['name']
    else:
        currentUser = ""
    return render_template(
        'product.html',
        currentUser=currentUser,
        loggedin=loggedin,
        supermarket=supermarket,
        product=product)


# Add product
@app.route('/addproduct/<int:supermarket_id>/', methods=['GET', 'POST'])
def addproduct(supermarket_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    if 'name' not in login_session \
            or supermarket is None \
            or supermarket.user.name != login_session['name']:
        flash('You are not authorized to add product on this market')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        if 'name' not in login_session:
            loggedin = 'name' in login_session
            return redirect(url_for('Home', loggedin=loggedin))
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        checkexisting = session.query(Products).filter_by(
            name=request.form['name']).first()
        if checkexisting is not None:
            flash('This Product Inserted before')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        newProduct = Products(
            name=request.form['name'],
            details=request.form['details'],
            price=request.form['price'],
            supermarket_id=supermarket.id,
            user_id=getUserID(
                login_session['email']),
            picture=filename)

        session.add(newProduct)
        session.commit()
        loggedin = 'name' in login_session
        return redirect(
            url_for(
                'market',
                supermarket_id=supermarket.id,
                loggedin=loggedin))
    else:
        loggedin = 'name' in login_session
        return render_template(
            'addproduct.html',
            supermarket=supermarket,
            loggedin=loggedin)


# Edit product
@app.route(
    '/editproduct/<int:supermarket_id>/<int:product_id>/',
    methods=[
        'GET',
        'POST'])
def editproduct(supermarket_id, product_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    product = session.query(Products).filter_by(id=product_id).first()
    if 'name' not in login_session \
            or supermarket is None or product is None \
            or supermarket.user.name != login_session['name'] \
            or supermarket.id != product.supermarket_id:
        flash('You are not authorized to edit this product')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    elif request.method == 'POST':
        if 'name' not in login_session:
            loggedin = 'name' in login_session
            return redirect(url_for('Home', loggedin=loggedin))
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        oldValues = session.query(Products).filter_by(
            name=product.name).first()
        checkexisting = session.query(Products).filter_by(
            name=request.form['name']).first()
        if checkexisting and checkexisting.id is not product.id:
            flash('There is a previous Product used this name')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            filename = oldValues.picture
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        oldValues.name = request.form['name']
        oldValues.price = request.form['price']
        oldValues.details = request.form['details']
        oldValues.picture = filename
        session.commit()
        flash('Product has been edited successfully')
        loggedin = 'name' in login_session
        return redirect(
            url_for(
                'market',
                supermarket_id=supermarket.id,
                loggedin=loggedin))
    else:
        loggedin = 'name' in login_session
        return render_template(
            'editproduct.html',
            supermarket=supermarket,
            product=product,
            loggedin=loggedin)


# Delete product
@app.route(
    '/deleteproduct/<int:supermarket_id>/<int:product_id>/',
    methods=[
        'GET',
        'POST'])
def deleteproduct(supermarket_id, product_id):
    supermarket = session.query(Supermarket).filter_by(
        id=supermarket_id).first()
    product = session.query(Products).filter_by(id=product_id).first()
    if 'name' not in login_session \
            or supermarket is None or product is None \
            or supermarket.user.name != login_session['name'] \
            or supermarket.id != product.supermarket_id:
        flash('You are not authorized to delete this product')
        loggedin = 'name' in login_session
        return redirect(url_for('Home', loggedin=loggedin))
    session.query(Products).filter_by(
        supermarket_id=supermarket.id,
        id=product.id).delete()
    flash('product has been deleted')
    loggedin = 'name' in login_session
    return redirect(
        url_for(
            'market',
            supermarket_id=supermarket.id,
            loggedin=loggedin))


# CSRF protection helpers
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            flash("Something went wrong!!")
            redirect(url_for('Home'))


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = app.secret_key
    return login_session['_csrf_token']


if __name__ == '__main__':
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.secret_key = 'AriMvfbGYr'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
