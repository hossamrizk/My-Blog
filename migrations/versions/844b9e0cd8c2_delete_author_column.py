"""Delete author column

Revision ID: 844b9e0cd8c2
Revises: 0b88cf17b273
Create Date: 2023-11-16 19:37:00.087257

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '844b9e0cd8c2'
down_revision = '0b88cf17b273'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('poster_id', sa.Integer(), nullable=True))
        batch_op.drop_constraint('posts_ibfk_1', type_='foreignkey')
        batch_op.create_foreign_key(None, 'users', ['poster_id'], ['id'])
        batch_op.drop_column('post_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('post_id', mysql.INTEGER(), autoincrement=False, nullable=True))
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('posts_ibfk_1', 'users', ['post_id'], ['id'])
        batch_op.drop_column('poster_id')

    # ### end Alembic commands ###