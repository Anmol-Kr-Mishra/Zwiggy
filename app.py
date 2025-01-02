import random
import string
# import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify , session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user 
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User , Customer , Cart , CartItem
import os
from datetime import datetime
import  io
from PIL import  Image, ImageDraw, ImageFont
from flask import Response
import time
from flask import g
from flask_mail import Mail,Message
from flask_mailman import Mail,EmailMessage




app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

#Mail Setup 

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=587
app.config['MAIL_USE_TLS']=True
app.config['MAIL_USERNAME']='zwiggycare@gmail.com'
app.config['MAIL_PASSWORD']='urvj aqxd xwih akpw'

mail=Mail(app)
# Database setup
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()  # Renamed from session to db_session to avoid conflicts

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
customer_login_manager = LoginManager()
customer_login_manager.init_app(app)

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must contain at least one digit."
    if not any(char in "!@#$%^&*()" for char in password):
        return "Password must contain at least one special character (!@#$%^&*())."
    return None



@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'error')
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(user_id)  # Updated to use db_session


@customer_login_manager.user_loader
def load_customer(customer_id):
    return db_session.get(User , customer_id)

def customer_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        customer_id = session.get('customer_id')  # Check if a customer is logged in
        if not customer_id:
            flash("Please Login First",'error')
            return redirect(url_for('user_register'))
        
        # Set g.current_customer for the request
        g.current_user = get_customer_by_id(customer_id)
        if g.current_user is None:
            flash("Invalid Customer",'error')
            return redirect(url_for('user_register'))
        
        return f(*args, **kwargs)
    return decorated_function


def get_customer_by_id(customer_id):
    return db_session.query(User).filter_by(id=customer_id).first()

@app.before_request
def set_current_customer():
    g.current_customer = customer_login_manager._load_user()
    
#ASYNCHRONOUS MAIL SYSTEM

def send_mail(subject,body,recipient):
    msg=EmailMessage(subject=subject,body=body,from_email='zwiggycare@gmail.com',to=[recipient])
    msg.send()

@app.route('/admin/admin_dashboard/<int:user_id>/approve', methods=['POST','GET'])
@login_required
def approve_user(user_id):
    if current_user.role not in ['admin','owner']:
        flash('You must be an admin to approve users.', 'error')
        return redirect(url_for('home'))

    user_to_approve = db_session.query(User).filter_by(id=user_id).one_or_none()
    if user_to_approve and current_user.role in ['owner','admin']:
        user_to_approve.is_approved = True
        user_to_approve.role='user'
        #Email Notification
        if user_to_approve.email is not None:
        #   msg=Message('User Account Approved', sender='zwiggycare@gmail.com',recipients=[user_to_approve.email])
        
        #   msg.body=f"Hello {user_to_approve.username},\n\n Your account pending for approval has just been approved.You can now login to the User Dashboard!"
        #   mail.send(msg)
          send_mail('Account Approved',f"Hello {user_to_approve.username},\n\n Your account pending for approval has just been approved.You can now login to the User Dashboard!",user_to_approve.email)
        #   flash("Notification send",'warning')
        else:
            flash("Email not available, notification not send",'info')
        db_session.commit()
        flash(f'User {user_to_approve.username} has been approved!', 'success')
    else:
        flash('You are not an admin!', 'error')
        return redirect(url_for('admin_restaurants'))

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/admin_dashboard/<int:user_id>/make_admin', methods=['POST','GET'])
@login_required
def make_admin(user_id):
    if current_user.role not in ['owner']:
        flash('You must be an owner to make admin.', 'error')
        return redirect(url_for('admin_dashboard'))

    user_to_make_admin = db_session.query(User).filter_by(id=user_id).one_or_none()
    if user_to_make_admin:
        # user_to_make_admin.is_approved = True
        user_to_make_admin.role='admin'
        db_session.commit()
        flash(f'User {user_to_make_admin.username} has been made admin!', 'success')
    else:
        flash('User not found.', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/admin_dashboard/<int:user_id>/reject_admin', methods=['POST','GET'])
@login_required
def reject_admin(user_id):
    if current_user.role not in ['owner']:
        flash('You must be an owner to remove admin.', 'error')
        return redirect(url_for('admin_dashboard'))

    user_to_reject_admin = db_session.query(User).filter_by(id=user_id).one_or_none()
    if user_to_reject_admin:
        # db_session.delete(user_to_reject)
        user_to_reject_admin.role ='user'
        # user_to_reject_admin.is_approved=False

        db_session.commit()
        flash(f'User {user_to_reject_admin.username} has been removed as admin!', 'info')
    else:
        flash('You are not an admin!', 'error')
        return redirect(url_for('admin_restaurants'))

    return redirect(url_for('admin_dashboard'))



@app.route('/admin/admin_dashboard/<int:user_id>/reject', methods=['POST','GET'])
@login_required
def reject_user(user_id):
    if current_user.role not in [ 'admin','owner']:
        flash('You must be an admin to reject users.', 'error')
        return redirect(url_for('admin_restaurants'))

    user_to_reject = db_session.query(User).filter_by(id=user_id).one_or_none()
    if user_to_reject and current_user.role in ['owner','admin']:
        # db_session.delete(user_to_reject)
        user_to_reject.role ='rejected'
        user_to_reject.is_approved=False

        db_session.commit()
        flash(f'User {user_to_reject.username} has been rejected!', 'info')
    else:
        flash('You are not an admin!', 'error')
        return redirect(url_for('admin_restaurants'))
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    
    if current_user.role not in [ 'admin' ,'owner'] :
        flash('You must be an admin to access this page.', 'error')
        return redirect(url_for('admin'))
    pending_users = db_session.query(User).filter(User.is_approved == False, User.role != 'customer').all()

    approved_users = db_session.query(User).filter(User.role != 'customer').all()
    approved_users_count = len(approved_users)
    pending_users_count = len(pending_users)
    # Correct usage with filter()
    all_users = db_session.query(User).filter(User.role != 'customer').all()

    
    return render_template('admin_dashboard.html',current_user=current_user, users=all_users,approved_users_count=approved_users_count, pending_users_count=pending_users_count)



#Admins
@app.route('/admin/')
@login_required

def admin():

    restaurants = db_session.query(Restaurant).all()  # Updated to use db_session
    return render_template('admin_restaurants.html', restaurants=restaurants,current_user=current_user)

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/restaurants/new/', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    if request.method == 'POST':
        name = request.form.get('name')
        restaurant1 = Restaurant(name=name)
        db_session.add(restaurant1)  # Updated to use db_session
        db_session.commit()
        return redirect(url_for('admin'))

    return render_template('newrestaurant.html')

@app.route('/admin/<int:restaurant_id>/delete/', methods=['POST'])
@login_required
def delete(restaurant_id):

    try:
        itemToDelete = db_session.query(Restaurant).filter_by(id=restaurant_id).one_or_none()  # Updated to use db_session
        if not itemToDelete:
            flash("Restaurant not found.", 'error')
            return redirect(url_for('admin'))

        db_session.delete(itemToDelete)  # Updated to use db_session
        db_session.commit()
        flash("Restaurant Deleted!", 'success')
    except Exception as e:
        flash(f"An error occurred: {e}", 'error')
    return redirect(url_for('admin'))


def generate_captcha_image(captcha_code):
    # Create a blank image with white background
    width, height = 120, 50
    image = Image.new('RGB', (width, height), color='white')

    # Initialize drawing context
    draw = ImageDraw.Draw(image)


    # Neon color for the text
    neon_color = (0, 0, 255)  # Neon blue
    glow_color = (255, 105, 180,80)  # Semi-transparent green for glow effect
    # glow_color2 = (0, 255, 0 , 80)
    # Set font (you can customize the font)
    font_path = "static/Arial.ttf"
    try:
        font = ImageFont.truetype(font_path, 36)
    except IOError:
        font = ImageFont.load_default()

    # Calculate the text size using textbbox (recommended method in Pillow 8.0+)
    text_bbox = draw.textbbox((0, 0), captcha_code, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]

    # Calculate position to center the text
    position = ((width - text_width) // 2, (height - text_height) // 2)
    # Add the CAPTCHA text to the image
     # Create a glowing effect by drawing shadows
    for offset in range(3, 0, -1):  # Draw shadow around the text
        draw.text((position[0] + offset, position[1] + offset), captcha_code, fill=glow_color, font=font)
    # for offset in range(4, 0, -1):  # Draw shadow around the text
    #     draw.text((position[0] + offset, position[1] + offset), captcha_code, fill=glow_color2, font=font)

    # Now draw the actual text on top
    draw.text(position, captcha_code, fill=neon_color, font=font)
    # Optionally, you can add random noise or lines for additional security

    # Return the image
    return image


    
def generate_captcha(length=4, use_digits=True, use_letters=True, use_both=True):
    # Define possible characters for CAPTCHA
    if use_both:
        characters = string.ascii_letters + string.digits  # Both letters and digits
    elif use_digits:
        characters = string.digits  # Only digits
    elif use_letters:
        characters = string.ascii_letters  # Only letters
    else:
        characters = string.digits  # Default to digits if no valid choice
    
    # Generate the CAPTCHA by randomly selecting characters
    captcha_code = ''.join(random.choice(characters) for _ in range(length))
    
    return captcha_code.upper()

@app.route('/captcha_image/')
def captcha_image():
    captcha_code = generate_captcha()
    
    # Save the CAPTCHA text to session
    session['captcha_solution'] = captcha_code
    
    # Generate CAPTCHA image
    image = generate_captcha_image(captcha_code)
    
    # Convert the image to a byte stream
    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    
    # Return the image as a response with the correct content type
    return Response(img_io, mimetype='image/png')



@app.route('/refresh_captcha', methods=['GET'])
def refresh_captcha():
    captcha_code = generate_captcha()
    session['captcha_solution'] = captcha_code  # Store the new solution in the session
    # Return the new CAPTCHA code or image URL (adjust based on your implementation)
    return render_template('login.html', captcha=captcha_code)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if 'captcha_solution' not in session :
        captcha_code = generate_captcha()
        session['captcha_solution'] = captcha_code
    if request.method == 'POST':
    
        username = request.form['username']
        password = request.form['password']
        
        captcha_answer = request.form['captcha']

        # Check CAPTCHA solution
        if captcha_answer != session.get('captcha_solution'):
            flash('Invalid CAPTCHA ! Please try again.', 'error')
            captcha_code = generate_captcha()  # Generate new CAPTCHA if answer is wrong
            session['captcha_solution'] = captcha_code
            return render_template('login.html', captcha=captcha_code)


        # Clear CAPTCHA solution after successful validation
        session.pop('captcha_solution', None)

        # Validate username and password
        user = db_session.query(User).filter(User.username == username).first()

        if user and check_password_hash(user.password, password):
            if user.role == 'customer':
                flash('Unauthorized Access!','error')
                return redirect(url_for('login'))

            if not user.is_approved:
                flash('Your account is pending approval. Please wait for an admin to approve you.', 'warning')
                return redirect(url_for('login'))
            #Email Notification
            if user.email is not None:
            #  msg=Message('New Login Detected', sender='zwiggycare@gmail.com',recipients=[user.email])
             current_time=datetime.now()
            #  msg.body=f"Hello {user.username},\n\n You just logged into your account at {current_time.strftime("%H:%M:%S")} . If this wasn't you , Please contact support immediately or try changing your password."
             send_mail('Login Detected',f"Hello {user.username},\n\n You just logged into your account at {current_time.strftime("%H:%M:%S")} . If this wasn't you , Please contact support immediately or try changing your password.",user.email)
            #  mail.send(msg)
            #  flash("Notification send",'warning')
            else:
             flash("Email not available, Kindly Update your email to receive notifications",'error')
            login_user(user)
            flash('Login successful!', 'success')
            session['login_time'] = time.time()
            return redirect(url_for('admin'))
        else:
            flash('Invalid username or password', 'error')
    
    captcha_code = session.get('captcha_solution', None)
    return render_template('login.html', captcha=captcha_code)



@app.route('/register/', methods=['GET', 'POST'])
def register():

    if 'captcha_solution' not in session or request.args.get('refresh_captcha'):
        captcha_code = generate_captcha()
        session['captcha_solution'] = captcha_code

    if request.method == 'POST':
        
        username = request.form['username']
        password = request.form['password']
        email= request.form['email']

        captcha_answer = request.form['captcha']
        # refresh_captcha = request.method=='GET'? True:False

        # Check CAPTCHA solution
        if captcha_answer != session.get('captcha_solution'):
            flash('Incorrect CAPTCHA. Please try again.', 'error')
            captcha_code = generate_captcha()  # Generate new CAPTCHA if answer is wrong
            session['captcha_solution'] = captcha_code
            return render_template('register.html', captcha=captcha_code)


        # Clear CAPTCHA solution after successful validation
        session.pop('captcha_solution', None)

        # Check if username already exists
        if db_session.query(User).filter_by(username=username).first():  # Updated to use db_session
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        # Hash the password before saving
        hashed_password = generate_password_hash(password,method="pbkdf2:sha256")

        new_user = User(username=username, password=hashed_password, role='user',is_approved = False,email=email)
        db_session.add(new_user)  # Updated to use db_session
        db_session.commit()

        flash('You are Registered! Approval Pending', 'success')
        return redirect(url_for('login'))
    captcha_code = session.get('captcha_solution', None)
    return render_template('register.html', captcha=captcha_code)

@app.route('/admin/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    restaurant = db_session.query(Restaurant).filter_by(id=restaurant_id).one()  # Updated to use db_session

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')

        if not name or not price:
            flash('Name and Price are required fields!', 'error')
            return redirect(url_for('newMenuItem', restaurant_id=restaurant_id))

        try:
            price = float(price)
        except ValueError:
            flash('Invalid price value. Please enter a valid number.', 'error')
            return redirect(url_for('newMenuItem', restaurant_id=restaurant_id))

        new_item = MenuItem(
            name=name,
            description=description,
            price=price,
            restaurant_id=restaurant.id
        )

        # Add to db_session and commit to the database
        db_session.add(new_item)  # Updated to use db_session
        db_session.commit()
        flash('New menu item added successfully!', 'success')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant.id))

    return render_template('newmenuitem.html', restaurant=restaurant)

@app.route('/admin/<int:restaurant_id>/<int:menu_id>/edit', methods=['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, menu_id):    
    editedItem = db_session.query(MenuItem).filter_by(id=menu_id).one()  # Updated to use db_session
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        db_session.add(editedItem)  # Updated to use db_session
        db_session.commit()
        flash('Menu item edited successfully!', 'success')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)

@app.route('/admin/<int:restaurant_id>/<int:menu_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, menu_id):
    itemToDelete = db_session.query(MenuItem).filter_by(id=menu_id).one()  # Updated to use db_session
    if request.method == 'POST':
        db_session.delete(itemToDelete)  # Updated to use db_session
        db_session.commit()
        flash("Item Deleted!", 'success')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)

# Customers

# #customers login mechanism

# customer_login_manager = LoginManager()
# customer_login_manager.init_app(app)
# # customer_login_manager.login_view = 'user_login'
#  #incase of failure

# @customer_login_manager.user_loader
# def load_customer(customer_id):
#     return db_session.get(Customer, customer_id)

# def customer_login_required(f):
#     from functools import wraps
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         customer_id = session.get('customer_id')
#         if not customer_id:
#             flash("Please Login First", 'error')
#             return redirect(url_for('customer_login'))
        
#         g.current_customer = load_customer(customer_id)
#         if g.current_customer is None:
#             flash("Invalid Customer", 'error')
#             return redirect(url_for('customer_login'))
        
#         return f(*args, **kwargs)
    
#     return decorated_function

# # Before request to set the current customer
# @app.before_request
# def set_current_customer():
#     customer_id = session.get('customer_id')
#     if customer_id:
#         g.current_customer = load_customer(customer_id)
#     else:
#         g.current_customer = None

#for changing passwords
@app.route('/change_password', methods=['GET', 'POST'])
@login_required 
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if new_password != confirm_new_password:
            flash('New passwords do not match!', 'error')
            return redirect(url_for('restaurants'))
        if new_password == current_password:
            flash('You have entered a previous password','error')
            return redirect(url_for('restaurants'))
        
        if not check_password_hash(current_user.password, current_password) :
           if not (current_password==session.get('otp')) :
            flash('Incorrect current password!', 'error')
            return redirect(url_for('restaurants'))
           session.pop('otp')

        hashed_password = generate_password_hash(new_password)

        current_user.password = hashed_password
        db_session.commit()

        flash('Password changed successfully!', 'success')
    
        
        return redirect(url_for('restaurants'))

    return render_template('change_password.html')


@app.route('/change_address', methods=['GET', 'POST'])
@login_required  
def change_address():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        updated_address = request.form.get('updated_address')

        # Check if the current password is correct
        if not check_password_hash(current_user.password, current_password):
            flash('Incorrect password!', 'error')
            return redirect(url_for('restaurants'))

        current_user.address = updated_address
        db_session.commit()

        flash('Address Updated successfully!', 'success')
        return redirect(url_for('restaurants'))

    return render_template('change_password.html')


@app.route('/change_mail', methods=['GET', 'POST'])
@login_required  
def change_mail():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        updated_mail = request.form.get('updated_mail')

        # Check if the current password is correct
        if not check_password_hash(current_user.password, current_password):
            flash('Incorrect password!', 'error')
            return redirect(url_for('restaurants'))
        is_unique=db_session.query(User).filter_by(email=updated_mail).first()
        if is_unique is None:
            current_user.email = updated_mail
            db_session.commit()
        else:
            flash('Email-id already exists!','error')
            return redirect(url_for('restaurants'))
        

        flash('Email-id Updated successfully!', 'success')
        return redirect(url_for('restaurants'))

    return render_template('change_password.html')


#OTP send to user via mail
@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    username = data.get('username')
    
    # Fetch user email from your database based on username (this is an example)
    user = db_session.query(User).filter_by(username=username).first()  # Replace this with actual DB logic
    if user is None :
        return jsonify({"success":False,"message":"Username not found"})
    
    user_email = user.email
    if user_email is None:
        return jsonify({"success": False, "message": "User Email not available"}), 404
    # flash('Sending OTP....','success')
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(4))
    # Store OTP in a session or database for validation later
    # You should use session or a secure method to store the OTP temporarily
    session['otp']=otp

    # Send OTP via email (Flask-Mail example)
    try:
        send_mail("One-Time Password",f"Your one time password for logging in is {otp}. Your password will be send to you once you are verified .",user_email)
        return jsonify({"success": True, "message": "OTP sent successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
#OTP verification
@app.route('/verify_otp',methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        username=request.form['username']
        user_otp=request.form['user_otp']
        otp=session.get('otp')
        user = db_session.query(User).filter_by(username=username).first()
        if user_otp == otp:
            session['customer_id'] = user.id
            login_user(user)
            # session.pop('otp',None)
            flash(f'Welcome {username}!', 'success')
            flash('Kindly change your password on priority basis, using the OTP as your Current Password','info')
            return redirect(url_for('restaurants'))


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/user_login/', methods=['GET', 'POST'])
def user_login():
    
    if 'captcha_solution' not in session or request.args.get('refresh_captcha'):
        captcha_code = generate_captcha()
        session['captcha_solution'] = captcha_code

    if request.method == 'POST':
    
        username = request.form['username']
        password = request.form['password']
        
        captcha_answer = request.form['captcha']

        # Check CAPTCHA solution
        if captcha_answer != session.get('captcha_solution'):
            flash('Invalid CAPTCHA ! Please try again.', 'error')
            captcha_code = generate_captcha()  # Generate new CAPTCHA if answer is wrong
            session['captcha_solution'] = captcha_code
            return render_template('user_register.html', captcha=captcha_code)

        session.pop('captcha_solution', None)

        # Validate username and password
        user = db_session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['customer_id'] = user.id


            login_user(user)
            flash(f'Welcome {username}!', 'success')
            return redirect(url_for('restaurants'))
        else:
            flash('Invalid username or password', 'error')

    captcha_code = session.get('captcha_solution', None)
    return render_template('user_register.html', captcha=captcha_code)

@app.route('/user_register/', methods=['GET', 'POST'])
def user_register():

    if 'captcha_solution' not in session or request.args.get('refresh_captcha'):
        captcha_code = generate_captcha()
        session['captcha_solution'] = captcha_code

    if request.method == 'POST':
        
        username = request.form['username']
        password = request.form['password']
        email= request.form['email']
        contact= request.form['contact']
        if len(contact)!= 10:
            flash('Contact no. should be of 10 digits','error')
            return redirect(url_for('user_register'))
        address = request.form['address']
        captcha_answer = request.form['captcha']
        # refresh_captcha = request.method=='GET'? True:False

        # Check CAPTCHA solution
        if captcha_answer != session.get('captcha_solution'):
            flash('Incorrect CAPTCHA. Please try again.', 'error')
            captcha_code = generate_captcha()  # Generate new CAPTCHA if answer is wrong
            session['captcha_solution'] = captcha_code
            return render_template('user_register.html', captcha=captcha_code)


        # Clear CAPTCHA solution after successful validation
        session.pop('captcha_solution', None)

        # Check if username already exists
        if db_session.query(User).filter_by(username=username).first():  # Updated to use db_session
            flash('Username already exists!', 'error')
            return redirect(url_for('user_register'))

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        new_customer = User(username=username, password=hashed_password,email=email,contact=contact,address=address,role='customer')
        db_session.add(new_customer)  # Updated to use db_session
        db_session.commit()
        return redirect(url_for('user_register'))
    captcha_code = session.get('captcha_solution', None)
    return render_template('user_register.html', captcha=captcha_code)

# CART 
@app.route('/add_to_cart/<int:menu_item_id>', methods=['POST'])
@customer_login_required
def add_item(menu_item_id ):
    # Fetch customer_id from session
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("Please log in to add items to your cart.", 'error')
        return redirect(url_for('user_register'))

    # Check if the menu item exists
    menu_item = db_session.query(MenuItem).filter_by(id=menu_item_id).first()
    if not menu_item:
        flash("The selected item does not exist.", 'error')
        return redirect(url_for('restaurants'))

    # Find or create the cart for this customer
    cart = db_session.query(Cart).filter_by(customer_id=customer_id).first()
    if not cart:
        cart = Cart(customer_id=customer_id)
        db_session.add(cart)
        db_session.commit()

    # Check if the item is already in the cart
    cart_item = db_session.query(CartItem).filter_by(cart_id=cart.id, menu_item_id=menu_item.id).first()
    if cart_item:
        cart_item.quantity += 1  # Increment quantity if item already in cart
    else:
        # Add new item to cart
        cart_item = CartItem(cart_id=cart.id, menu_item_id=menu_item.id, quantity=1)
        db_session.add(cart_item)
    restaurant_id=session.get('restaurant_id')
    db_session.commit()
    flash(f"Added {menu_item.name} to your cart!", 'success')
    return redirect(url_for('UserMenu', restaurant_id=restaurant_id))



@app.route('/view_cart')
@customer_login_required
def view_cart_page():
    # Fetch customer_id from session
    customer_id = session.get('customer_id')
    if not customer_id:
        flash('You must log in first.', 'error')
        return redirect(url_for('user_register'))

    # Query the CartItems using the customer's Cart
    cart = db_session.query(Cart).filter_by(customer_id=customer_id).first()
    if not cart or not cart.items:
        # flash('Your cart is empty.', 'info')
        return render_template('view_cart.html', cart_items=[], total_price=0)

    # Calculate total price and pass cart items
    def sanitize_price(price_str):
    # Remove any non-numeric characters except for a decimal point
        return float(''.join(c for c in price_str if c.isdigit() or c == '.'))

    total_price = "{:.2f}".format(sum([sanitize_price(item.menu_item.price) * item.quantity for item in cart.items]))
    # def apply_discount():
    #     d = (random.randint(1,20))
    #     d=d/100
    #     return d
    total_price = "{:.2f}".format(float(total_price) -(0.1*float(total_price)))

    return render_template('view_cart.html', cart_items=cart.items, total_price=total_price)



@app.route('/update_cart_quantity', methods=['POST'])
@customer_login_required
def update_cart_quantity():
    """
    Route to update the quantity of a specific cart item.
    """
    try:
        # Fetch customer_id from session
        customer_id = session.get('customer_id')
        if not customer_id:
            flash('You must log in first.', 'error')
            return redirect(url_for('user_login'))
        
        # Get item_id and new quantity from form data
        cart_item_id = request.form.get('cart_item_id')
        new_quantity = int(request.form.get('quantity', -1))
        if new_quantity == -1:
            item_to_remove = db_session.query(CartItem).filter_by(id=cart_item_id).first()
            if item_to_remove:
                db_session.delete(item_to_remove)
                db_session.commit()
                flash("Item removed from the cart.",'success')
                return redirect(url_for('view_cart_page'))
            else :
                return "Nothing Happened!"


        # Validate quantity
        if new_quantity < 1:
            flash('Quantity must be at least 1.', 'error')
            return redirect(url_for('view_cart_page'))

        # Fetch the cart item
        cart_item = db_session.query(CartItem).filter_by(id=cart_item_id).first()

        if not cart_item:
            flash('Cart item not found.', 'error')
        else:
            # Update the quantity
            cart_item.quantity = new_quantity
            db_session.commit()
            flash('Quantity updated successfully.', 'success')

    except Exception as e:
        db_session.rollback()
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('view_cart_page'))

@app.route('/checkout', methods=['POST'])
@customer_login_required
def checkout_page():
    message = checkout(current_user.id)
    return render_template('checkout.html', message=message)





def add_to_cart(customer_id, menu_item_id, quantity=1):
    # Fetch the customer and menu item
    customer = db_session.query(User).filter_by(id=customer_id).first()
    menu_item = db_session.query(MenuItem).filter_by(id=menu_item_id).first()

    if customer and menu_item:
        # If customer doesn't have a cart, create a new one
        if not customer.cart:
            cart = Cart(customer_id=customer_id)
            db_session.add(cart)
            db_session.commit()

        # Fetch the customer's cart
        cart = customer.cart

        # Check if the item already exists in the cart
        cart_item = db_session.query(CartItem).filter_by(cart_id=cart.id, menu_item_id=menu_item.id).first()

        if cart_item:
            # If item exists, increase the quantity
            cart_item.quantity += quantity
        else:
            # Otherwise, add a new item to the cart
            cart_item = CartItem(cart_id=cart.id, menu_item_id=menu_item.id, quantity=quantity)
            db_session.add(cart_item)

        db_session.commit()
        return "Item added to cart"
    else:
        return "Customer or Menu Item not found"
    

@app.route('/remove_cart',methods=['POST'])
def remove_cart( menu_item_id: int = None):

    
    customer_id = session.get('customer_id')
    try:
        # Query the cart for the customer
        cart = db_session.query(Cart).filter_by(customer_id=customer_id).first()
        
        if not cart:
            return "Cart does not exist for this customer."

        if menu_item_id:
            # Remove a specific item from the cart
            item_to_remove = db_session.query(CartItem).filter_by(cart_id=cart.id, menu_item_id=menu_item_id).first()
            if item_to_remove:
                db_session.delete(item_to_remove)
                db_session.commit()
                return f"Item with ID {menu_item_id} removed from the cart."
            else:
                return "Item not found in the cart."
        else:
            # Remove all items from the cart
            db_session.query(CartItem).filter_by(cart_id=cart.id).delete()
            db_session.commit()
            return "All items removed from the cart."
    except Exception as e:
        db_session.rollback()
        return f"An error occurred: {str(e)}"

def view_cart(customer_id):
    print(db_session)
    return db_session.query(CartItem).filter_by(id=customer_id).all()



def checkout(customer_id):
    customer = db_session.query(Customer).filter_by(id=customer_id).first()
    if customer and customer.cart:
        cart = customer.cart
        cart_items = db_session.query(CartItem).filter_by(cart_id=cart.id).all()
        
        total_price = sum([item.total_price for item in cart_items])

        # Here you can handle the payment process (e.g., integrating with Stripe or PayPal)

        # After successful payment, clear the cart
        db_session.delete(cart)
        db_session.commit()

        return f"Checkout successful! Total Price: ${total_price:.2f}"
    else:
        return "Cart is empty or customer not found"





#restaurants 
@app.route('/restaurants/')
def restaurants():
    restaurants = db_session.query(Restaurant).all()  # Updated to use db_session
    
    return render_template('restaurants.html', restaurants=restaurants,current_customer=current_user)

@app.route('/restaurants/JSON/')
def restaurantsJSON():
    restaurants = db_session.query(Restaurant).all()  # Updated to use db_session
    return jsonify(RestaurantNames=[i.serialize() for i in restaurants])

@app.route('/restaurants/<int:restaurant_id>/')
# @customer_login_required
def UserMenu(restaurant_id):
    session['restaurant_id']=restaurant_id
    restaurant = db_session.query(Restaurant).filter_by(id=restaurant_id).one()  # Updated to use db_session
    items = db_session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()  # Updated to use db_session
    # cart_items=db_session.query(CartItem).filter_by(cart_id= cart_id).all()
    return render_template('user_menu.html', restaurant=restaurant, items=items)

@app.route('/restaurants/<int:restaurant_id>/usermenu/')
@login_required
def restaurantMenu(restaurant_id):
    restaurant = db_session.query(Restaurant).filter_by(id=restaurant_id).one()  # Updated to use db_session
    items = db_session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()  # Updated to use db_session
    return render_template('menu.html', restaurant=restaurant, items=items)

@app.route('/search', methods=['GET'])
def search_restaurant():
    query = request.args.get('query', '').strip()  # Get the search term
    
    if query:
        # Search logic
        results = (
            db_session.query(Restaurant)
            .filter(Restaurant.name.ilike(f"%{query}%"))
            .all()
        )
        if not results:
            flash("No results were Found !",'error')
            return redirect(url_for('restaurants'))
    else:
        # Show all restaurants if no query
        results = db_session.query(Restaurant).all()

    # Pass the query and results to the template
    return render_template('restaurants.html', query=query, restaurants=results)

@app.route('/user_logout/')
@customer_login_required
def user_logout():
    logout_user()
    session.pop('customer_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('restaurants'))
@app.route('/restaurants/<int:restaurant_id>/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = db_session.query(Restaurant).filter_by(id=restaurant_id).one()  # Updated to use db_session
    items = db_session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()  # Updated to use db_session
    return jsonify(MenuItems=[i.serialize() for i in items])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8085)