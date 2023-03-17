package com.example.app.service;

import com.example.app.exception.ResourceNotFoundException;
import com.example.app.model.entity.CustomerEntity;
import com.example.app.model.internal.CustomerDetailModel;
import com.example.app.repository.CustomerRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class CustomerServiceImpl implements CustomerService {
    private CustomerRepository customerRepository;

    @Override
    public List<CustomerEntity> getAllCustomers() {
        return customerRepository.findAll();
    }

    @Override
    public Optional<CustomerEntity> getCustomerById(Integer id) {
        return customerRepository.findById(id);
    }

    @Override
    public List<CustomerDetailModel> getAllCustomersDetail() {
        return customerRepository.findAllCustomersDetail();
    }

    @Override
    public Optional<CustomerDetailModel> getCustomerDetailById(Integer id) {
        return customerRepository.findCustomerDetailById(id);
    }

    @Override
    public CustomerEntity addCustomer(CustomerEntity entity) {
        return customerRepository.save(entity);
    }

    @Override
    public CustomerEntity updateCustomer(CustomerEntity entity) {
        var id = entity.getCustomerId();
        var resource = customerRepository.findById(id);
        if (resource.isPresent()) {
            return customerRepository.save(entity);
        } else {
            throw new ResourceNotFoundException("Customer not found with id '" + id + "'");
        }
    }

    @Override
    public void deleteCustomerById(Integer id) {
        customerRepository.deleteById(id);
    }
}
