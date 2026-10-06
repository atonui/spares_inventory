"""Equipment administration HTTP schemas."""
from typing import Optional
from pydantic import BaseModel


class EquipmentResponse(BaseModel):
    id: int
    equipment_name: str
    make: str
    model: str
    serial_number: str
    assigned_user_id: Optional[int]
    assigned_user_name: Optional[str]
    calibration_cert_number: Optional[str]
    calibration_authority: Optional[str]
    calibration_date: Optional[str]
    next_calibration_date: Optional[str]
    status: str
    notes: Optional[str]
    days_until_calibration: Optional[int]


class CreateEquipmentRequest(BaseModel):
    equipment_name: str
    make: str
    model: str
    serial_number: str
    assigned_user_id: Optional[int] = None
    calibration_cert_number: Optional[str] = None
    calibration_authority: Optional[str] = None
    calibration_date: Optional[str] = None
    next_calibration_date: Optional[str] = None
    notes: Optional[str] = None


class UpdateEquipmentRequest(BaseModel):
    equipment_name: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    assigned_user_id: Optional[int] = None
    calibration_cert_number: Optional[str] = None
    calibration_authority: Optional[str] = None
    calibration_date: Optional[str] = None
    next_calibration_date: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class TransferEquipmentRequest(BaseModel):
    to_user_id: Optional[int] = None
    notes: Optional[str] = None


class UpdateCalibrationRequest(BaseModel):
    calibration_cert_number: str
    calibration_authority: str
    calibration_date: str
    next_calibration_date: str
    notes: Optional[str] = None


class EquipmentStatsResponse(BaseModel):
    total_equipment: int
    my_equipment: int
    due_soon: int
    overdue: int
