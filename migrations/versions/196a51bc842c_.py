"""empty message

Revision ID: 196a51bc842c
Revises: f0f49050068f
Create Date: 2023-11-09 11:06:26.421828

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '196a51bc842c'
down_revision = 'f0f49050068f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('password_hash',
               existing_type=sa.VARBINARY(length=128),
               type_=sa.String(length=128),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('password_hash',
               existing_type=sa.String(length=128),
               type_=sa.VARBINARY(length=128),
               existing_nullable=True)

    # ### end Alembic commands ###
