#provides the tools and functions to work with MySQL databases in Python.
import mysql.connector

# Handle the database setup tasks.
def setup_database():
    mydb = mysql.connector.connect(
        host='localhost',#specifies the database server location (in this case, 'localhost' refers to the local machine)
        user='root',
        password='123456789'
    )

    my_cursor = mydb.cursor() #Cursors are used to execute SQL queries and fetch results from the database.
    # This line executes an SQL query to create a new database named 'our_users'. The CREATE DATABASE statement is used to create a new database in MySQL.
    my_cursor.execute("CREATE DATABASE our_users")
    my_cursor.execute("SHOW DATABASES")

    for db in my_cursor:
        print(db)

#This code checks if the script is being run as the main program (not imported as a module) and, if so, calls the setup_database function. This ensures that the database setup tasks are executed when the script is run.
if __name__ == '__main__':
    setup_database()
