import logging
import os
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from datetime import datetime
from io import BytesIO
from collections import defaultdict
import pandas as pd
from flask import Flask, abort, send_file, jsonify, make_response, session
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField, BooleanField, DateTimeField
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
from flask import Flask, jsonify, redirect, url_for, flash, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pyotp import TOTP