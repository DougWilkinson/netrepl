# file.py
class File:
	def __init__(self, path="", size=-1, exists=False, is_dir=False) -> None:
		self.path = path
		self.hash = ""
		self.size = size
		self.exists = exists
		self.date_modified = 0.0
		self.is_dir = is_dir

