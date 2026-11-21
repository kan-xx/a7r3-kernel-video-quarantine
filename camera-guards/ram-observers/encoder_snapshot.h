/* Static constructor chain identifies these objects, not a RAM signature scan.
 * Root 639fc970 -> 639fc424, channel managers -> 63d5173c,
 * facade -> 639fa7f0, core -> 63d49b42, parameters -> 639ebea8.
 * Reads only. Ring counters are NOT sensor frame or dropped-frame counters. */
struct encoder_sample {
    uint32_t parameter_va, manager_selection, state_va, state_raw;
    uint32_t profile_va, profile_index;
    uint32_t ring[5], capacity, qos[7];
    unsigned char request[88], profile[100], create_parameters[16];
};
static int encoder_snapshot(struct encoder_sample *s,unsigned channel) {
    const uint32_t root=0x64139e18u;
    const uint32_t offsets[]={0x2f8,0xf148,0x1df98};
    unsigned char head[24],source[4],qos[28];uint32_t v;
    memset(s,0,sizeof *s);s->profile_index=0xffffffffu;
    if(channel>=3||phys(root,&v,4)||v!=0x646960e8u)return 20;
    uint32_t manager=root+offsets[channel],core=manager+0x18,parameter=core+0x10;
    s->parameter_va=parameter;
    if(phys(parameter,&v,4)||v!=0x64695ac0u||phys(manager,head,8))return 21;
    s->manager_selection=w(head,4);
    if(phys(core,head,16)||w(head,0)!=root+0x2c8+0x10*channel)return 22;
    if(phys(w(head,0),source,4)||w(source,0)!=channel)return 23;
    if(phys(w(head,4),&s->state_va,4)||phys(s->state_va,head,8)||w(head,0)!=core)return 24;
    s->state_raw=w(head,4);
    if(phys(parameter+0x6e4,s->request,sizeof s->request)||
       phys(parameter+0x7e0,&s->profile_va,4)||
       phys(parameter+0x4048,s->ring,20)||
       phys(parameter+0x768,&s->capacity,4)||
       phys(parameter+0xe8a0+0x94,qos,sizeof qos)||
       phys(core+0xe984,s->create_parameters,16))return 25;
    for(unsigned i=0;i<7;i++)s->qos[i]=w(qos,4*i);
    if(s->profile_va){
        if(s->profile_va<0x63e24ed0u||s->profile_va>=0x63e288a0u||
            (s->profile_va-0x63e24ed0u)%100)return 26;
        s->profile_index=(s->profile_va-0x63e24ed0u)/100;
        if(phys(s->profile_va,s->profile,100))return 27;
    }
    return 0;
}
static void encoder_print(const struct encoder_sample *s){
    uint32_t begin=s->ring[0],end=s->ring[1],producer=s->ring[2],consumer=s->ring[3];
    int valid=end>begin&&s->capacity==end-begin&&producer>=begin&&producer<end&&consumer>=begin&&consumer<end;
    uint32_t free_bytes=valid?(producer<consumer?consumer-producer:end-begin-producer+consumer):0;
    printf("{\"parameter_va\":%u,\"state_raw\":%u,\"manager_selection\":%u,\"profile_va\":%u,\"profile_index\":%u,\"request\":\"",s->parameter_va,s->state_raw,s->manager_selection,s->profile_va,s->profile_index);
    hex(s->request,88);printf("\",\"create_parameters\":\"");hex(s->create_parameters,16);
    printf("\",\"ring\":[%u,%u,%u,%u],\"ring_capacity\":%u,\"ring_valid\":%s,\"original_free_bytes_formula\":%u,\"cyclic_index\":%u,\"qos_raw\":[",begin,end,producer,consumer,s->capacity,valid?"true":"false",free_bytes,s->ring[4]);
    for(unsigned i=0;i<7;i++)printf("%s%u",i?",":"",s->qos[i]);
    printf("],\"profile\":\"");if(s->profile_va)hex(s->profile,100);printf("\"}");
}
