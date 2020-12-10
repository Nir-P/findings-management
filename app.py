import bcrypt
from flask import Flask, g, redirect, render_template, request, session as ses, url_for
from sqlalchemy import create_engine, Column, Date, exc, Integer, Table, String, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from datetime import date

import os

app = Flask(__name__)

app.secret_key = os.urandom(24)

Base = declarative_base()
DATABASE_CONN = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_CONN, echo=True)
Session = sessionmaker(engine)


role = Table(
    "users_role", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("role_name.id"))
)

team = Table(
    "users_team", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("team_id", Integer, ForeignKey("team_name.id"))
)

report_user = Table(
    "report_user", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("report_id", Integer, ForeignKey("report.id"))
)


class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    creation_date = Column(Date, nullable=False, default=date.today())
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)

    roles = relationship("RoleName", secondary="users_role")
    reports = relationship('Report', secondary='report_user')


class RoleName(Base):
    __tablename__ = "role_name"
    id = Column(Integer, primary_key=True)
    role_name = Column(String, nullable=False, unique=True)


class TeamName(Base):
    __tablename__ = "team_name"
    id = Column(Integer, primary_key=True)
    team_name = Column(String, nullable=False, unique=True)


class Finding(Base):
    __tablename__ = "finding"
    id = Column(Integer, primary_key=True)
    finding_header = Column(String, nullable=False)
    finding_content = Column(String)
    report_id = Column(Integer, ForeignKey("report.id"), nullable=False)


class Recommendations(Base):
    __tablename__ = "recommendations"
    id = Column(Integer, primary_key=True)
    recommendation_header = Column(String)
    recommendation_content = Column(String)
    finding_id = Column(Integer, ForeignKey("finding.id"), nullable=False, unique=True)


class Report(Base):
    __tablename__ = "report"
    id = Column(Integer, primary_key=True)
    report_name = Column(String, nullable=False, unique=True)

    users = relationship("Users", secondary="report_user")


def create_user(username, password, first_name, last_name):
    session = Session()
    user = Users(
        username=username,
        password=bcrypt.hashpw(password=password.encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8'),
        creation_date=date.today(),
        first_name=first_name,
        last_name=last_name
        )
    session.add(user)
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def check_username_password(username, password):
    session = Session()
    user = session.query(Users).filter_by(username=username).first()
    session.close()
    if user is not None and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return user
    return None


def add_report_and_give_user_per(report_name, username):
    session = Session()
    report = Report(report_name=report_name)
    user_to_report = session.query(Users).filter(Users.username == username).first()
    user_to_report.reports.append(report)
    session.add(report)
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def all_user_reports(username):
    session = Session()
    all_report = session.query(Report).join(Report.users).filter(Users.username == username).all()
    session.close()
    return all_report


def all_user_finding(username):
    session = Session()
    all_finding = []
    all_report = session.query(Report).join(Report.users).filter(Users.username == username).all()
    for report in all_report:
        findings = session.query(Finding).filter(Finding.report_id == report.id).all()
        for finding in findings:
            all_finding.append(finding.id)
    session.close()
    return all_finding


def add_finding(finding_header, finding_content, report_id):
    session = Session()
    finding = Finding(
        finding_header=finding_header,
        finding_content=finding_content,
        report_id=report_id,
        )
    session.add(finding)
    session.flush()
    finding_id = finding.id
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return finding_id


def update_finding(finding_id, head, content):
    session = Session()
    finding = session.query(Finding).filter(Finding.id == finding_id).first()
    finding.finding_header = head
    finding.finding_content = content
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def delete_finding(finding_id):
    session = Session()
    finding_to_delete = session.query(Finding).filter(Finding.id == finding_id).first()
    session.delete(finding_to_delete)
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def add_recommendations(recommendation_header, recommendation_content, finding_id):
    session = Session()
    recommended = Recommendations(
        recommendation_header=recommendation_header,
        recommendation_content=recommendation_content,
        finding_id=finding_id
    )
    session.add(recommended)
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def update_recommendation(finding_id, head, content):
    session = Session()
    recommendation_to_update = session.query(Recommendations).filter(Recommendations.finding_id == finding_id).first()
    recommendation_to_update.recommendation_header = head
    recommendation_to_update.recommendation_content = content
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def delete_recommendations(finding_id):
    session = Session()
    recommendation_to_delete = session.query(Recommendations).filter(Recommendations.finding_id == finding_id).first()
    session.delete(recommendation_to_delete)
    try:
        session.commit()
        session.close()
    except exc.SQLAlchemyError:
        session.rollback()
        session.close()
        return False
    return True


def get_all_finding_recommendation_for_report(report_id):
    session = Session()
    find_recomm = {}
    finding = session.query(Finding).filter(Finding.report_id == report_id)
    recommendation = session.query(Recommendations).join(Finding).filter(Finding.report_id == report_id)
    for f in finding:
        find_recomm[f.id] = [f.finding_header, f.finding_content]
    for r in recommendation:
        find_recomm[r.finding_id].extend([r.recommendation_header, r.recommendation_content])
    return find_recomm.items()


Base.metadata.create_all(bind=engine)  # this line create the database


@app.route('/')
def homepage():
    if g.username:
        return render_template("homepage_logged.html", first_name=g.user_fn)
    return render_template("homepage.html")


@app.route('/sign_up', methods=["GET", "POST"])
def sign_up():
    if request.method == "GET":
        return render_template("sign_up.html")
    elif request.method == "POST":
        rf = request.form
        username = rf["username"]
        password = rf["password"]
        first_name = rf["first-name"]
        last_name = rf["last-name"]
        if create_user(username, password, first_name, last_name):
            return render_template("sign_up_success.html")
        return render_template("sign_up_failed.html")


@app.route('/sign_in', methods=["GET", "POST"])
def sign_in():
    if request.method == "GET":
        return render_template("sign_in.html")
    elif request.method == "POST":
        ses.pop("user_first_name", None)
        ses.pop("username", None)
        ses.pop("report", None)
        rf = request.form
        user = check_username_password(rf["username"], rf["password"])
        if user is not None:
            ses["user_first_name"] = user.first_name
            ses["username"] = user.username
            return redirect(url_for("user_area"))
        return render_template("sign_in.html")


@app.route('/user_area')
def user_area():
    if g.username:
        user_reports = all_user_reports(g.username)
        return render_template("user_area.html", first_name=g.user_fn, user_reports=user_reports)
    return redirect(url_for("homepage"))


@app.route('/disconnect')
def user_disconnect():
    ses.pop("user_first_name", None)
    ses.pop("username", None)
    ses.pop("report", None)
    return render_template("homepage.html")


@app.route('/add_report', methods=["GET", "POST"])
def add_report():
    if g.username:
        if request.method == "GET":
            user_reports = all_user_reports(g.username)
            return render_template("add_report.html", first_name=g.user_fn, user_reports=user_reports)
        elif request.method == "POST":
            report_name = request.form["report-name"]
            add_report_and_give_user_per(report_name, g.username)
            return redirect(url_for("user_area"))
    return redirect(url_for("homepage"))


@app.route('/reports/<report>')
def show_report(report):
    if g.username:
        user_reports = all_user_reports(g.username)
        this_report = [(rep.id, rep.report_name) for rep in user_reports if rep.id == int(report)]
        finding_recommendation = get_all_finding_recommendation_for_report(int(report))
        if this_report:
            return render_template("user_area_report.html", first_name=g.user_fn, user_reports=user_reports, this_report=this_report[0], finding_recommendation=enumerate(finding_recommendation))
    return "You don't have permission to this report"


@app.route('/reports/<report>/add_finding_and_recommendation', methods=["GET", "POST"])
def add_finding_and_recommendation(report):
    if g.username:
        user_reports = all_user_reports(g.username)
        this_report = [(rep.id, rep.report_name) for rep in user_reports if rep.id == int(report)]
        if this_report:
            if request.method == "GET":
                return render_template("add_finding_and_recommendation.html", first_name=g.user_fn, user_reports=user_reports, this_report=this_report[0], report=report)
            elif request.method == "POST":
                rf = request.form
                finding_id = add_finding(rf["finding_header"], rf["finding_text"], int(report))  # add finding and get his autoincrement id
                add_recommendations(rf["recommendation_header"], rf["recommendation_text"], finding_id)
                return redirect(url_for("show_report", report=report))
        else:
            return "You don't have permission to this report"


@app.route('/<report>/finding/<finding_recommendation>/delete')
def delete_finding_and_recommendation(report, finding_recommendation):
    finding_recommendation = int(finding_recommendation)
    if g.username and (finding_recommendation in all_user_finding(g.username)):
        delete_recommendations(finding_recommendation)
        delete_finding(finding_recommendation)
        return redirect(url_for("show_report", report=report))
    else:
        return "You don't have permission to this action"


@app.route('/reports/<report>/<finding_recommendation>/update', methods=["GET", "POST"])
def update_finding_and_recommendation(report, finding_recommendation):
    finding_recommendation = int(finding_recommendation)
    if g.username and (finding_recommendation in all_user_finding(g.username)):
        user_reports = all_user_reports(g.username)
        this_report = [(rep.id, rep.report_name) for rep in user_reports if rep.id == int(report)]
        if request.method == "GET":
            rep = get_all_finding_recommendation_for_report(int(report))
            for finding_num, content in rep:
                if finding_num == int(finding_recommendation):
                    content_retrieve = content
            return render_template("finding_recommendation_update.html", content_retrieve=content_retrieve, first_name=g.user_fn, user_reports=user_reports, this_report=this_report[0], report=report)
        elif request.method == "POST":
            rf = request.form
            update_finding(finding_recommendation, rf["finding_header"], rf["finding_text"])
            update_recommendation(finding_recommendation, rf["recommendation_header"], rf["recommendation_text"])
            return redirect(url_for("show_report", report=report))
    else:
        return "You don't have permission to this action"


@app.before_request
def before_request():
    g.user_fn = None
    g.username = None
    if "username" in ses:
        g.user_fn = ses["user_first_name"]
        g.username = ses["username"]
