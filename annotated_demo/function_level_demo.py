import xml.etree.ElementTree as ET

# safe usage
root = ET.parse("file.xml")

# vulnerable call
user_input = "<root></root>"
result = ET.fromstring(user_input)  # XXE 취약
