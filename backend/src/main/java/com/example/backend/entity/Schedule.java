package com.example.backend.entity;

import com.example.backend.entity.Pet;
import lombok.*;


import javax.persistence.*;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor(staticName = "build")
@Table(name = "SCHEDULE_TBL")
@Builder
public class Schedule {
    @Id
    @GeneratedValue
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumns({
            @JoinColumn(name="petName", referencedColumnName="petName"),
            @JoinColumn(name="inviter", referencedColumnName="inviter")
    })
    private Pet pet;
    private String schedule;
    private String date;
    private String hm;
    private Integer period;
    private Integer notice;
    private Integer isCompleted;
}