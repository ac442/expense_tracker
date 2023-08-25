import logging
import os
from datetime import datetime
from io import BytesIO
from collections import defaultdict
import pandas as pd
from flask import Flask, flash, redirect, render_template, url_for, request, abort, send_file
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import matplotlib.pyplot as plt
import io
from wtforms.validators import Optional
from base64 import b64encode
import base64
from dateutil.relativedelta import relativedelta
from collections import Counter
from flask import flash, redirect, render_template, request, url_for
import numpy as np
from datetime import datetime, timedelta
import random
