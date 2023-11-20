"""added username

Revision ID: 24348a120fc0
Revises: dfba4aaab23c
Create Date: 2023-11-14 13:50:43.953027

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '24348a120fc0'
down_revision = 'dfba4aaab23c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=20), nullable=False))
        batch_op.create_unique_constraint(None, ['username'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('username')

    # ### end Alembic commands ###
