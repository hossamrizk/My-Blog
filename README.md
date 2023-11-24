# Flask Blog

This Flask Blog repository houses a blog application created using Flask. It's the product of a journey through a comprehensive Flask course on YouTube. The blog offers functionalities typical of a Flask-based web application, allowing users to create, read, update, and delete blog posts.

## Features

- **User Authentication:** Users can register, log in, and log out securely.
- **CRUD Operations:** Create, Read, Update, and Delete blog posts.
- **User-specific Dashboards:** Customized dashboards for users, displaying their posts and account information.

## Installation

To run this application locally, follow these steps:

1. Clone the repository: `git clone https://github.com/hossamrizk/My-Blog.git`
2. Navigate to the project directory: `cd My-Blog`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment:
   - On Windows: `venv\Scripts\activate`
   - On macOS and Linux: `source venv/bin/activate`
5. Install the required dependencies: `pip install -r requirements.txt`
6. Set up the database:
   - Initialize the database: `python create_db.py`
7. Run the application: `python app.py`
8. Access the application in your browser at `http://localhost:5000`

## Usage

- Register a new account or log in if you already have one.
- Create, edit, or delete blog posts from your dashboard.
- Explore the blog by browsing through existing posts.

## Further Reading

To delve deeper into Flask and web development:

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Real Python Flask Tutorials](https://realpython.com/tutorials/flask/)
- [Miguel Grinberg's Flask Mega-Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)

## Contributing

If you'd like to contribute to this project, feel free to open an issue or submit a pull request. All contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Please note that this README is a basic outline and can be expanded upon with more detailed information about the project's structure, features, and deployment instructions.*
