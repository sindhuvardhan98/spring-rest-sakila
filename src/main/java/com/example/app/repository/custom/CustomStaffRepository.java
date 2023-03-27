package com.example.app.repository.custom;

import com.example.app.model.internal.extra.StaffDetailModel;

import java.util.List;
import java.util.Optional;

public interface CustomStaffRepository {
    List<StaffDetailModel> findAllStaffsDetail();

    Optional<StaffDetailModel> findStaffDetailById(Integer staffId);
}
