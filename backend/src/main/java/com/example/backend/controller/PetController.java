package com.example.backend.controller;

import com.example.backend.entity.Pet;
import com.example.backend.entity.User;
import com.example.backend.repository.PetRepository;
import com.example.backend.service.PetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.modelmapper.ModelMapper;
import com.example.backend.repository.UserRepository;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/pet")
public class PetController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PetRepository petRepository;
    @Autowired
    private ModelMapper modelMapper;
    @Autowired
    private HttpServletRequest request;

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<PetService> createPet(@RequestBody PetService petService) {
        Pet pet = modelMapper.map(petService, Pet.class);
        Pet savedPet = petRepository.save(pet);
        PetService savedPetService = modelMapper.map(savedPet, PetService.class);
        return ResponseEntity.ok(savedPetService);
    }

    private String getCurrentUserInviter(HttpServletRequest request) {
        return request.getHeader("inviter"); // 예시로 header에서 inviter 정보를 가져옴
    }

    @GetMapping("/{email}")
    public ResponseEntity<List<PetService>> getPet(@PathVariable("email") String email, HttpServletRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            String inviter = user.getInviter();
            String currentUserInviter = getCurrentUserInviter(request);
            if (inviter.equals(currentUserInviter)) { // 현재 로그인한 사용자와 inviter가 같은 경우에만 조회
                List<Pet> pets = petRepository.findByInviter(inviter);
                List<PetService> petServices = pets.stream()
                        .map(pet -> modelMapper.map(pet, PetService.class))
                        .collect(Collectors.toList());
                return ResponseEntity.ok(petServices);
            }
        }
        return ResponseEntity.notFound().build();
    }


    @GetMapping
    public ResponseEntity<List<PetService>> getPets() {
        List<Pet> pets = petRepository.findAll();
        List<PetService> petServices = pets.stream()
                .map(pet -> modelMapper.map(pet, PetService.class))
                .collect(Collectors.toList());
        return ResponseEntity.ok(petServices);
    }

    @PutMapping("/{petId}")
    public ResponseEntity<PetService> updatePet(@PathVariable("petId") Long petId, @RequestBody PetService petService) {
        Optional<Pet> optionalPet = petRepository.findById(petId);
        if (optionalPet.isPresent()) {
            Pet pet = optionalPet.get();
            modelMapper.map(petService, pet);
            Pet updatedPet = petRepository.save(pet);
            PetService updatedPetService = modelMapper.map(updatedPet, PetService.class);
            return ResponseEntity.ok(updatedPetService);
        }
        return ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{petId}")
    public ResponseEntity<Void> deletePet(@PathVariable("petId") Long petId) {
        petRepository.deleteById(petId);
        return ResponseEntity.noContent().build();
    }
}

