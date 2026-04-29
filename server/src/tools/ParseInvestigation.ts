export const parseInvestigationDetails = (investigations:any) => {
    if(investigations.size === 0) {
        return;
    }
    const parsedInvestigationDetails = investigations.map((investigation:any) => {
        return {
            investigationId:investigation.id,
            rrn:investigation.rrn,
            InvestigationName: investigation.title,
            status:investigation.status,
            alerts:investigation.alerts,
            created_at:investigation.created_time
        }
    })
    console.log(parsedInvestigationDetails);
    

    return parsedInvestigationDetails
}
