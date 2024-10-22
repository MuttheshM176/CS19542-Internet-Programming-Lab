from flask import Flask, render_template, redirect, request, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = 'your_secret_key'


app.config["MONGO_URI"] = "mongodb://localhost:27017/elearning_db"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user'] = email
            flash('Login successful!', 'success')  

            if email == 'admin@example.com':
                session['admin'] = True
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if mongo.db.users.find_one({'email': email}):
            flash('Email already exists. Please use a different email.', 'warning')  
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({'email': email, 'password': hashed_password})
        flash('Account created successfully! Please log in.', 'success') 
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/admin')
def admin_dashboard():
    if 'admin' in session:
        courses = mongo.db.courses.find()
        return render_template('admin_dashboard.html', courses=courses)
    else:
        return redirect(url_for('login'))


@app.route('/add_course', methods=['POST'])
def add_course():
    if 'admin' in session:
        course_name = request.form['course_name'].strip()
        course_description = request.form['course_description'].strip()
        course_syllabus = request.form['course_syllabus'].strip()

        if not course_name or not course_description or not course_syllabus:
            flash('All fields are required.', 'danger') 
            return redirect(url_for('admin_dashboard'))


        mongo.db.courses.insert_one({
            'name': course_name,
            'description': course_description,
            'syllabus': course_syllabus,
            'enrolled_students': 0
        })
        flash(f'Course "{course_name}" added successfully!', 'success')  
        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('login'))



@app.route('/delete_course/<course_id>', methods=['POST'])
def delete_course(course_id):
    if 'admin' in session:
        course = mongo.db.courses.find_one({'_id': ObjectId(course_id)})

        if course:
            mongo.db.courses.delete_one({'_id': ObjectId(course_id)})
            flash(f'Course "{course["name"]}" deleted successfully!', 'success')  # Success for deletion
        else:
            flash('Course not found.', 'danger')  # Danger for non-existent course

        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('login'))

# User Dashboard Route
@app.route('/user')
def user_dashboard():
    if 'user' in session:
        courses = mongo.db.courses.find()
        return render_template('user_dashboard.html', courses=courses)
    else:
        return redirect(url_for('login'))

# Enrollment Route
@app.route('/enroll/<course_id>', methods=['POST'])
def enroll(course_id):
    if 'user' in session:
        # Increment the number of enrolled students for the course
        result = mongo.db.courses.update_one(
            {'_id': ObjectId(course_id)},
            {'$inc': {'enrolled_students': 1}}
        )

        # Check if the update was successful and flash appropriate message
        if result.modified_count > 0:
            flash('Successfully enrolled in the course!', 'success')  # Success for enrollment
        else:
            flash('Failed to enroll in the course.', 'danger')  # Danger for failed enrollment

        return redirect(url_for('user_dashboard'))
    else:
        flash('You need to log in to enroll in a course.', 'warning')  # Warning for non-authenticated user
        return redirect(url_for('login'))

# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # Clear session data
    flash('You have been logged out.', 'info')  # Info for logout
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
