# IMPORTS
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db, requires_roles
from lottery.forms import DrawForm
from models import Draw

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@login_required
@requires_roles('user')
def lottery():
    return render_template('lottery/lottery.html', name=current_user.firstname)


# view all draws that have not been played
@lottery_blueprint.route('/create_draw', methods=['POST'])
@login_required
@requires_roles('user')
def create_draw():
    form = DrawForm()

    if form.validate_on_submit():
        number_set = {form.number1.data, form.number2.data, form.number3.data, form.number4.data, form.number5.data,
                      form.number6.data}
        if len(number_set) != 6:
            flash("There must be 6 unique numbers entered into the draw")
            return render_template('lottery/lottery.html', name=current_user.firstname, form=form)
        for i in number_set:
            if i < 0 or 60 < i:
                flash("Your entries must be between 0 and 60")
                return render_template('lottery/lottery.html', name=current_user.firstname, form=form)

        sorted(number_set)

        submitted_numbers = ""

        for i in number_set:
            submitted_numbers = submitted_numbers + str(i) + ' '

        submitted_numbers = submitted_numbers[:-1]
        # create a new draw with the form data.
        # Sym Encryption Functionality:
        # new_draw = Draw(user_id=current_user.id, numbers=current_user.encryption(submitted_numbers),
        #                         master_draw=False, lottery_round=0)
        new_draw = Draw(user_id=current_user.id, numbers=current_user.assem_encryption(submitted_numbers),
                        master_draw=False, lottery_round=0)

        # add the new draw to the database
        db.session.add(new_draw)
        db.session.commit()

        # re-render lottery.page
        flash('Draw %s submitted.' % submitted_numbers)
        return redirect(url_for('lottery.lottery'))

    return render_template('lottery/lottery.html', name=current_user.firstname, form=form)


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@login_required
@requires_roles('user')
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()

    if len(playable_draws) != 0:

        for draw in playable_draws:
            # Sym Encryption Functionality:
            # draw.numbers = current_user.decryption(draw.numbers)
            draw.numbers = current_user.assem_decryption(draw.numbers)

        return render_template('lottery/lottery.html', playable_draws=playable_draws)

    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@login_required
@requires_roles('user')
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(been_played=True, user_id=current_user.id).all()

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@login_required
@requires_roles('user')
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False, user_id=current_user.id).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()


