"""empty message

Revision ID: 66b9f2a25d17
Revises: 212d596f1c5e
Create Date: 2023-08-28 21:12:48.598740

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '66b9f2a25d17'
down_revision = '212d596f1c5e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_2fa_enabled', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('secret_key', sa.String(length=16), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('secret_key')
        batch_op.drop_column('is_2fa_enabled')

    # ### end Alembic commands ###
