import mysql.connector
from faker import faker

fake = Faker()
mydb= mysql.connector.connect(host="localhost", user="root",passwd="")
my_cursor = mydb.coursor()