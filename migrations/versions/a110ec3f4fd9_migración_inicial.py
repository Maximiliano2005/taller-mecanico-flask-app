"""Migración inicial

Revision ID: a110ec3f4fd9
Revises: 
Create Date: 2025-07-21 21:04:57.657665

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a110ec3f4fd9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('cliente',
    sa.Column('id_cliente', sa.Integer(), nullable=False),
    sa.Column('nombre_completo', sa.String(length=100), nullable=False),
    sa.Column('celular', sa.String(length=20), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id_cliente')
    )
    op.create_table('repuesto',
    sa.Column('id_repuesto', sa.Integer(), nullable=False),
    sa.Column('nombre_repuesto', sa.String(length=100), nullable=False),
    sa.Column('descripcion', sa.Text(), nullable=True),
    sa.Column('marca_repuesto', sa.String(length=50), nullable=True),
    sa.Column('precio_compra', sa.Float(), nullable=False),
    sa.Column('precio_venta', sa.Float(), nullable=False),
    sa.Column('stock_actual', sa.Integer(), nullable=False),
    sa.Column('stock_minimo', sa.Integer(), nullable=False),
    sa.Column('ubicacion_fisica', sa.String(length=100), nullable=True),
    sa.Column('modelos_compatibles', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id_repuesto')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password', sa.String(length=200), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('vehiculo',
    sa.Column('id_vehiculo', sa.Integer(), nullable=False),
    sa.Column('id_cliente', sa.Integer(), nullable=False),
    sa.Column('patente', sa.String(length=20), nullable=False),
    sa.Column('marca', sa.String(length=50), nullable=False),
    sa.Column('modelo', sa.String(length=50), nullable=False),
    sa.Column('anio', sa.Integer(), nullable=True),
    sa.Column('kilometraje', sa.Integer(), nullable=True),
    sa.Column('notas_vehiculo', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['id_cliente'], ['cliente.id_cliente'], ),
    sa.PrimaryKeyConstraint('id_vehiculo'),
    sa.UniqueConstraint('patente')
    )
    op.create_table('orden_trabajo',
    sa.Column('id_ot', sa.Integer(), nullable=False),
    sa.Column('id_vehiculo', sa.Integer(), nullable=False),
    sa.Column('fecha_ingreso', sa.DateTime(), nullable=False),
    sa.Column('descripcion_trabajo', sa.Text(), nullable=False),
    sa.Column('mecanico_asignado', sa.String(length=100), nullable=True),
    sa.Column('valor_mano_obra', sa.Float(), nullable=False),
    sa.Column('fecha_entrega_real', sa.DateTime(), nullable=True),
    sa.Column('valor_total_servicio', sa.Float(), nullable=False),
    sa.Column('estado', sa.String(length=50), nullable=False),
    sa.ForeignKeyConstraint(['id_vehiculo'], ['vehiculo.id_vehiculo'], ),
    sa.PrimaryKeyConstraint('id_ot')
    )
    op.create_table('detalle_ot',
    sa.Column('id_detalle_ot', sa.Integer(), nullable=False),
    sa.Column('id_ot', sa.Integer(), nullable=False),
    sa.Column('id_repuesto', sa.Integer(), nullable=False),
    sa.Column('cantidad', sa.Integer(), nullable=False),
    sa.Column('precio_unitario_al_momento', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['id_ot'], ['orden_trabajo.id_ot'], ),
    sa.ForeignKeyConstraint(['id_repuesto'], ['repuesto.id_repuesto'], ),
    sa.PrimaryKeyConstraint('id_detalle_ot')
    )
    op.create_table('venta',
    sa.Column('id_venta', sa.Integer(), nullable=False),
    sa.Column('fecha_venta', sa.DateTime(), nullable=False),
    sa.Column('id_cliente', sa.Integer(), nullable=True),
    sa.Column('total_venta', sa.Float(), nullable=False),
    sa.Column('tipo_venta', sa.String(length=50), nullable=False),
    sa.Column('id_ot_asociada', sa.Integer(), nullable=True),
    sa.Column('saldo_pendiente', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['id_cliente'], ['cliente.id_cliente'], ),
    sa.ForeignKeyConstraint(['id_ot_asociada'], ['orden_trabajo.id_ot'], ),
    sa.PrimaryKeyConstraint('id_venta')
    )
    op.create_table('detalle_venta',
    sa.Column('id_detalle_venta', sa.Integer(), nullable=False),
    sa.Column('id_venta', sa.Integer(), nullable=False),
    sa.Column('id_repuesto', sa.Integer(), nullable=False),
    sa.Column('cantidad', sa.Integer(), nullable=False),
    sa.Column('precio_venta_unitario_al_momento', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['id_repuesto'], ['repuesto.id_repuesto'], ),
    sa.ForeignKeyConstraint(['id_venta'], ['venta.id_venta'], ),
    sa.PrimaryKeyConstraint('id_detalle_venta')
    )
    op.create_table('pago',
    sa.Column('id_pago', sa.Integer(), nullable=False),
    sa.Column('id_venta', sa.Integer(), nullable=False),
    sa.Column('monto', sa.Float(), nullable=False),
    sa.Column('metodo_pago', sa.String(length=50), nullable=False),
    sa.Column('descripcion', sa.String(length=255), nullable=True),
    sa.Column('fecha_pago', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['id_venta'], ['venta.id_venta'], ),
    sa.PrimaryKeyConstraint('id_pago')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('pago')
    op.drop_table('detalle_venta')
    op.drop_table('venta')
    op.drop_table('detalle_ot')
    op.drop_table('orden_trabajo')
    op.drop_table('vehiculo')
    op.drop_table('user')
    op.drop_table('repuesto')
    op.drop_table('cliente')
    # ### end Alembic commands ###
