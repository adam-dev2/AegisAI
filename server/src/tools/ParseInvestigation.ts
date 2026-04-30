export const parseInvestigationDetails = (investigation:any) => {
    return {
        id:investigation.id,
        rrn:investigation.rrn,
        InvestigationName: investigation.title,
        status:investigation.status,
        alerts:investigation.alerts,
        created_at:investigation.created_time
    }
}
