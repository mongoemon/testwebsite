import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('SELECT username FROM users')
users = c.fetchall()
print("Users in DB:", users)
conn.close()
